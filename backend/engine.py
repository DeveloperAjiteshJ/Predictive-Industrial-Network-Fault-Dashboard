from __future__ import annotations

import logging
import json
import math
import ipaddress
import socket
import sys
import threading
import time
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from collections import Counter, defaultdict, deque
from dataclasses import asdict
from pathlib import Path
from statistics import mean, median, pstdev
from typing import Any, Deque, Iterable, Optional

import numpy as np

from .config import BASELINE_SECONDS, CHANNELS, ESCALATION_WINDOW_SECONDS, MAX_CHART_POINTS, RECOVERY_WINDOW_SECONDS, ROLLING_BASIS_SECONDS, SEVERITY_ORDER, WINDOW_SECONDS
from .models import (
    AdaptiveBaseline,
    AlertEvent,
    ChannelConfig,
    ChannelId,
    ChannelSnapshot,
    DeviceState,
    FaultConfig,
    FaultType,
    FlowState,
    HeartbeatState,
    MetricSnapshot,
    PacketEvent,
    Severity,
    SourceMode,
)
from .storage import SQLiteStore


def _severity_rank(value: Severity) -> int:
    return SEVERITY_ORDER[value.value]


def _worst(*values: Severity) -> Severity:
    return max(values, key=_severity_rank) if values else Severity.normal


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _flow_id(src: str, dst: str, sport: int, dport: int) -> str:
    return f"{src}:{sport}->{dst}:{dport}"


class ChannelEngine:
    def __init__(self, channel: str, store: SQLiteStore) -> None:
        self.channel = channel
        self.store = store
        self.config = ChannelConfig(channel=channel)
        self.lock = threading.RLock()
        self._log = logging.getLogger(f"backend.engine.{channel}")
        self.started_at = time.time()
        self.last_packet_ts = self.started_at
        self.last_tick_ts = self.started_at
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_times: Deque[float] = deque(maxlen=ROLLING_BASIS_SECONDS)
        self.byte_times: Deque[tuple[float, int]] = deque(maxlen=ROLLING_BASIS_SECONDS)
        self.broadcast_times: Deque[float] = deque(maxlen=ROLLING_BASIS_SECONDS)
        self.multicast_times: Deque[float] = deque(maxlen=ROLLING_BASIS_SECONDS)
        self.arp_times: Deque[float] = deque(maxlen=ROLLING_BASIS_SECONDS)
        self.udp_times: Deque[float] = deque(maxlen=ROLLING_BASIS_SECONDS)
        self.arp_targets: dict[str, dict] = defaultdict(lambda: {"requests": deque(maxlen=2000), "replies": 0, "reply_seen": False, "requests_per_min": deque(maxlen=10)})
        self.gratuitous_arp: dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=100))
        self.heartbeat_states: dict[tuple[str, str], HeartbeatState] = {}
        self.stp_root_mac: str = ""
        self.stp_path_cost: int = 0
        self.stp_last_change: float = 0.0
        self.stp_tc_times: Deque[float] = deque(maxlen=500)
        self.device_states: dict[str, DeviceState] = {}
        self.flow_states: dict[str, FlowState] = {}
        self.pending_silence: dict[str, float] = {}
        self.silence_events: dict[str, float] = {}
        self.packet_history: Deque[dict] = deque(maxlen=MAX_CHART_POINTS)
        self.metric_history: dict[str, Deque[dict]] = defaultdict(lambda: deque(maxlen=MAX_CHART_POINTS))
        self.series_buffers: dict[str, Deque[dict]] = defaultdict(lambda: deque(maxlen=MAX_CHART_POINTS))
        self.active_alerts: dict[str, AlertEvent] = {}
        self.alert_history: Deque[AlertEvent] = deque(maxlen=500)
        self.summary_counts: Counter[str] = Counter()
        self.last_snapshot: ChannelSnapshot = ChannelSnapshot(channel=channel, ts=self.started_at)
        self._baseline_ready_at = self.started_at + BASELINE_SECONDS
        self._display_baselines: dict[str, float | int | str] = {}
        self._baseline_models: dict[str, AdaptiveBaseline] = {}
        self.alert_mutes: dict[str, bool] = self.store.read_metric_mutes(channel)
        self._trend_values: dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=3))
        self._metric_non_normal_since: dict[str, float] = {}
        self._metric_last_normal_at: dict[str, float] = {}
        self._metric_last_value: dict[str, float] = {}
        self._metric_last_severity: dict[str, Severity] = {}
        self._metric_issue_counts: Counter[str] = Counter()
        self._name_cache: dict[str, str] = {}
        self._name_jobs: dict[str, Any] = {}
        self._name_executor: ThreadPoolExecutor | None = ThreadPoolExecutor(max_workers=2, thread_name_prefix=f"{channel}-name")
        self._closed = False
        self._last_snapshot_save_ts = 0.0
        self._baseline_last_saved_ts: dict[str, float] = {}
        self._pending_baseline_saves: dict[str, tuple[str, dict]] = {}

    @contextmanager
    def _locked(self, section: str):
        thread_name = threading.current_thread().name
        wait_started = time.perf_counter()
        self._log.debug("[%s] %s waiting for engine.lock in %s", self.channel, thread_name, section)
        self.lock.acquire()
        acquired_at = time.perf_counter()
        wait_seconds = acquired_at - wait_started
        if wait_seconds >= 0.01:
            self._log.warning("[%s] %s acquired engine.lock in %s after %.3fs", self.channel, thread_name, section, wait_seconds)
        else:
            self._log.debug("[%s] %s acquired engine.lock in %s after %.3fs", self.channel, thread_name, section, wait_seconds)
        try:
            yield
        finally:
            held_seconds = time.perf_counter() - acquired_at
            self.lock.release()
            self._log.debug("[%s] %s released engine.lock in %s after %.3fs", self.channel, thread_name, section, held_seconds)

    def configure(self, config: ChannelConfig) -> None:
        with self._locked("configure"):
            self.config = config

    def _device_key(self, event: PacketEvent) -> str:
        if event.src_mac:
            return event.src_mac.lower()
        if event.src_ip:
            return event.src_ip
        return f"device-{event.channel}"

    def _update_device(self, event: PacketEvent) -> DeviceState:
        key = self._device_key(event)
        device = self.device_states.get(key)
        if device is None:
            device = DeviceState(device_id=key, src_mac=event.src_mac.lower(), src_ip=event.src_ip, first_seen=event.timestamp, last_seen=event.timestamp)
            self.device_states[key] = device
        if device.packet_count > 0:
            delta = event.timestamp - device.last_seen
            if delta > 0:
                device.intervals.append(delta)
                if len(device.intervals) >= 5:
                    device.expected_interval = float(median(device.intervals))
                    jitter = [abs(v - device.expected_interval) for v in device.intervals]
                    device.avg_jitter_ms = float(mean(jitter) * 1000.0)
                    device.max_jitter_ms = float(max(jitter) * 1000.0)
        device.last_seen = event.timestamp
        device.packet_count += 1
        device.byte_count += event.length
        if event.src_port is not None:
            device.source_ports.add(int(event.src_port))
        if event.is_multicast and event.dst_ip:
            device.destination_groups.add(event.dst_ip)
        if device.silent:
            device.silence_event_ended = event.timestamp
            device.silence_duration = event.timestamp - device.silence_started
            device.silent = False
        return device

    def record_packet(self, event: PacketEvent) -> None:
        with self._locked("record_packet"):
            self.total_packets += 1
            self.total_bytes += event.length
            self.last_packet_ts = event.timestamp
            self.packet_times.append(event.timestamp)
            self.byte_times.append((event.timestamp, event.length))
            if event.is_broadcast:
                self.broadcast_times.append(event.timestamp)
            if event.is_multicast:
                self.multicast_times.append(event.timestamp)
            if event.is_arp:
                self.arp_times.append(event.timestamp)
            if event.is_udp:
                self.udp_times.append(event.timestamp)

            device = self._update_device(event)

            if event.is_arp:
                self._record_arp(event)
            if event.is_heartbeat:
                self._record_heartbeat(event)
            if event.protocol == "STP":
                self._record_stp(event)
            if event.is_udp and event.src_ip and event.dst_ip and event.src_port is not None and event.dst_port is not None:
                self._record_flow(event)

    def _record_arp(self, event: PacketEvent) -> None:
        if event.arp_opcode == 1:
            target = event.arp_target_ip or event.dst_ip or "unknown"
            data = self.arp_targets[target]
            data["requests"].append(event.timestamp)
            if event.is_broadcast:
                self.broadcast_times.append(event.timestamp)
        elif event.arp_opcode == 2:
            sender = event.arp_sender_ip or event.src_ip or "unknown"
            data = self.arp_targets[sender]
            data["replies"] = int(data["replies"]) + 1
            data["reply_seen"] = True
            if event.is_gratuitous_arp:
                self.gratuitous_arp[sender].append(event.timestamp)

    def _record_heartbeat(self, event: PacketEvent) -> None:
        key = (event.src_mac.lower() or event.src_ip, event.heartbeat_protocol)
        state = self.heartbeat_states.get(key)
        if state is None:
            state = HeartbeatState(device_mac=key[0], protocol=event.heartbeat_protocol, last_seen=event.timestamp, observed_since=event.timestamp)
            self.heartbeat_states[key] = state
        if state.last_seen:
            delta = event.timestamp - state.last_seen
            if delta > 0:
                state.intervals.append(delta)
                if len(state.intervals) >= 5 and state.baseline_interval <= 0:
                    state.baseline_interval = float(median(state.intervals))
        state.last_seen = event.timestamp

    def _record_stp(self, event: PacketEvent) -> None:
        if event.stp_root_mac:
            if not self.stp_root_mac:
                self.stp_root_mac = event.stp_root_mac
            elif self.stp_root_mac != event.stp_root_mac:
                self.stp_root_mac = event.stp_root_mac
                self.stp_last_change = event.timestamp
        if event.stp_path_cost:
            if self.stp_path_cost == 0:
                self.stp_path_cost = event.stp_path_cost
            elif self.stp_path_cost != event.stp_path_cost:
                self.stp_path_cost = event.stp_path_cost
                self.stp_last_change = event.timestamp
        if event.stp_topology_change:
            self.stp_tc_times.append(event.timestamp)

    def _record_flow(self, event: PacketEvent) -> None:
        flow_id = _flow_id(event.src_ip, event.dst_ip, int(event.src_port or 0), int(event.dst_port or 0))
        flow = self.flow_states.get(flow_id)
        if flow is None:
            flow = FlowState(flow_id=flow_id, src_ip=event.src_ip, dst_ip=event.dst_ip, src_port=int(event.src_port or 0), dst_port=int(event.dst_port or 0), first_seen=event.timestamp, last_seen=event.timestamp)
            self.flow_states[flow_id] = flow
        if flow.timestamps:
            delta = event.timestamp - flow.timestamps[-1]
            if delta > 0:
                flow.intervals.append(delta)
                if len(flow.intervals) >= 5 and not flow.monitored:
                    arr = np.asarray(flow.intervals, dtype=float)
                    mean_interval = float(np.mean(arr))
                    std_interval = float(np.std(arr))
                    if mean_interval > 0 and std_interval / mean_interval < 0.2:
                        flow.monitored = True
                        flow.expected_interval = mean_interval
                        flow.baseline_jitter = std_interval
                        self._display_baselines[f"jitter:{flow_id}"] = std_interval
                        self._display_baselines[f"loss:{flow_id}"] = 0.0
        flow.timestamps.append(event.timestamp)
        flow.last_seen = event.timestamp
        if flow.expected_interval <= 0 and len(flow.intervals) >= 5:
            flow.expected_interval = float(median(flow.intervals))

    def _rolling_packets_per_sec(self, now: float) -> int:
        cutoff = now - WINDOW_SECONDS
        while self.packet_times and self.packet_times[0] < cutoff:
            self.packet_times.popleft()
        return len(self.packet_times)

    def _rolling_bytes_per_sec(self, now: float) -> int:
        cutoff = now - WINDOW_SECONDS
        while self.byte_times and self.byte_times[0][0] < cutoff:
            self.byte_times.popleft()
        return sum(size for _, size in self.byte_times)

    def _window_count(self, items: Deque[float], now: float, window: int = WINDOW_SECONDS) -> int:
        cutoff = now - window
        while items and items[0] < cutoff:
            items.popleft()
        return len(items)

    def _baseline_key(self, metric_id: str) -> AdaptiveBaseline:
        baseline = self._baseline_models.get(metric_id)
        if baseline is None:
            baseline = AdaptiveBaseline()
            self._baseline_models[metric_id] = baseline
        return baseline

    def _resolve_name(self, ip: str, fallback: str = "") -> str:
        if not ip:
            return fallback
        if self._closed or sys.is_finalizing():
            return fallback or ip
        try:
            ipaddress.ip_address(ip)
        except Exception:
            return fallback or ip
        cached = self._name_cache.get(ip)
        if cached:
            return cached
        job = self._name_jobs.get(ip)
        if job is None:
            def lookup() -> str:
                try:
                    return socket.gethostbyaddr(ip)[0]
                except Exception:
                    return ""

            executor = self._name_executor
            if executor is None:
                return fallback or ip
            try:
                job = executor.submit(lookup)
            except RuntimeError:
                return fallback or ip
            self._name_jobs[ip] = job
        if job.done():
            try:
                resolved = str(job.result() or "")
            except Exception:
                resolved = ""
            display = resolved or fallback or ip
            self._name_cache[ip] = display
            self._name_jobs.pop(ip, None)
            return display
        return fallback or ip

    def _ip_label(self, ip: str) -> str:
        if not ip:
            return "unknown ip"
        name = self._resolve_name(ip)
        return f"{name} ({ip})" if name and name != ip else ip

    def _affected_scope(self, keys: Iterable[str]) -> tuple[str, int]:
        unique = {str(key) for key in keys if key}
        count = len(unique)
        if count <= 0:
            return "none", 0
        if count == 1:
            return "single", 1
        return "multiple", count

    def _compact_labels(self, labels: Iterable[str], limit: int = 3) -> str:
        unique = [label for label in dict.fromkeys(str(label) for label in labels if label)]
        if not unique:
            return ""
        if len(unique) == 1:
            return unique[0]
        if len(unique) == 2:
            return f"{unique[0]} and {unique[1]}"
        head = ", ".join(unique[:limit - 1])
        remaining = len(unique) - (limit - 1)
        if remaining > 0:
            return f"{head}, and {remaining} more"
        return ", ".join(unique)

    def _device_label(self, device: DeviceState) -> str:
        if device.src_ip:
            return self._ip_label(device.src_ip)
        if device.src_mac:
            return self._resolve_name(device.src_mac, device.device_id)
        return device.device_id

    def _flow_label(self, flow: FlowState) -> str:
        src = self._ip_label(flow.src_ip) if flow.src_ip else flow.src_ip or "unknown source"
        dst = self._ip_label(flow.dst_ip) if flow.dst_ip else flow.dst_ip or "unknown destination"
        if flow.dst_ip:
            try:
                if ipaddress.ip_address(flow.dst_ip).is_multicast:
                    return f"multicast stream from {src} to group {dst}"
            except Exception:
                pass
        return f"stream from {src} to {dst}"

    def _recent_devices(self, now: float, window: float = 60.0) -> list[DeviceState]:
        return [device for device in self.device_states.values() if now - device.last_seen <= window]

    def _scope_phrase(self, scope: str, single: str, multiple: str) -> str:
        return single if scope == "single" else multiple

    def shutdown(self) -> None:
        self._closed = True
        executor = self._name_executor
        self._name_executor = None
        if executor is not None:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)

    def _baseline_profile(self, metric_id: str, fallback: float) -> tuple[float, float, int, bool]:
        baseline = self._baseline_models.get(metric_id)
        if baseline is None or baseline.samples == 0:
            return float(fallback), 0.0, 0, False
        return baseline.mean, baseline.stddev, baseline.samples, baseline.reliable

    def _adaptive_multiplier(self, samples: int) -> float:
        if samples < 3:
            return 2.25
        if samples < 8:
            return 1.75
        if samples < 20:
            return 1.35
        if samples < 50:
            return 1.15
        return 1.0

    def _baseline_learning_allowed(self, metric_id: str, severity: Severity, *, allow_advisory: bool = False) -> bool:
        now = self.last_tick_ts
        if severity != Severity.normal:
            return False
        if metric_id not in self._metric_non_normal_since:
            return True
        return now - self._metric_last_normal_at.get(metric_id, now) >= RECOVERY_WINDOW_SECONDS

    def _learn_baseline(self, metric_id: str, value: float, severity: Severity, *, allow_advisory: bool = False, weight: float = 0.18) -> None:
        if value is None:
            return
        if not self._baseline_learning_allowed(metric_id, severity, allow_advisory=allow_advisory):
            return
        baseline = self._baseline_key(metric_id)
        baseline.observe(float(value), weight=weight, now=self.last_tick_ts)
        self._display_baselines[metric_id] = baseline.mean
        if baseline.samples < 20:
            return
        last_saved = self._baseline_last_saved_ts.get(metric_id, 0.0)
        if baseline.samples > 1 and self.last_tick_ts - last_saved < 60.0:
            return
        self._pending_baseline_saves[metric_id] = (
            f"{baseline.mean:.6f}",
            {
                "mean": baseline.mean,
                "stddev": baseline.stddev,
                "samples": baseline.samples,
                "reliable": baseline.reliable,
                "updated_ts": baseline.last_updated,
            },
        )
        self._baseline_last_saved_ts[metric_id] = self.last_tick_ts

    def is_alert_muted(self, metric_id: str) -> bool:
        return bool(self.alert_mutes.get(metric_id, False))

    def get_alert_mutes(self) -> dict[str, bool]:
        return dict(self.alert_mutes)

    def set_alert_mute(self, metric_id: str, muted: bool) -> None:
        muted = bool(muted)
        with self._locked("set_alert_mute"):
            self.alert_mutes[metric_id] = muted
            self.store.set_metric_mute(self.channel, metric_id, muted)
            if not muted:
                return
            alert = self.active_alerts.pop(metric_id, None)
            if alert is None:
                return
            alert.active = False
            alert.resolved = True
            self.store.update_latest_alert(
                self.channel,
                metric_id,
                acknowledged=alert.acknowledged,
                resolved=True,
                active=False,
                duration_seconds=alert.duration_seconds,
                last_seen=alert.last_seen,
            )

    def _baseline_average(self, series: Deque[float], fallback: float = 0.0) -> float:
        values = list(series)
        if not values:
            return fallback
        return float(mean(values))

    def _build_metric(self, metric_id: str, label: str, value: float | int | str, baseline: float | int | str | None, severity: Severity, interpretation: str, recommendation: str, confidence: int, trend: str = "flat", correlation_note: str = "") -> MetricSnapshot:
        current_duration = 0.0
        if severity != Severity.normal:
            current_duration = max(0.0, self.last_packet_ts - self._metric_non_normal_since.get(metric_id, self.last_packet_ts))
        baseline_model = self._baseline_models.get(metric_id)
        baseline_samples = baseline_model.samples if baseline_model is not None else 0
        learning_state = "stable" if baseline_model is not None and baseline_model.reliable else "learning"
        occurrence_count = self._metric_issue_counts.get(metric_id, 0)
        return MetricSnapshot(
            metric_id=metric_id,
            label=label,
            severity=severity,
            value=value,
            baseline=baseline,
            interpretation=interpretation,
            recommendation=recommendation,
            correlation_note=correlation_note,
            confidence=confidence,
            occurrence_count=occurrence_count,
            baseline_samples=baseline_samples,
            learning_state=learning_state,
            trend=trend,
            current_duration=current_duration,
        )

    def _severity_from_thresholds(self, value: float, advisory: float, degraded: float, critical: float) -> Severity:
        if value >= critical:
            return Severity.critical
        if value >= degraded:
            return Severity.degraded
        if value >= advisory:
            return Severity.advisory
        return Severity.normal

    def _trend(self, metric_id: str, value: float) -> str:
        series = self._trend_values[metric_id]
        series.append(value)
        if len(series) < 3:
            return "flat"
        if series[-1] > series[-2] > series[-3]:
            return "worsening"
        if series[-1] < series[-2] < series[-3]:
            return "improving"
        return "flat"

    def _escalate_if_needed(self, metric_id: str, snapshot: MetricSnapshot) -> MetricSnapshot:
        now = self.last_packet_ts
        if snapshot.severity == Severity.normal:
            was_non_normal = metric_id in self._metric_non_normal_since
            self._metric_non_normal_since.pop(metric_id, None)
            self._metric_issue_counts.pop(metric_id, None)
            if was_non_normal:
                self._metric_last_normal_at[metric_id] = now
            snapshot.occurrence_count = 0
            return snapshot

        if metric_id not in self._metric_non_normal_since:
            self._metric_non_normal_since[metric_id] = now
        self._metric_issue_counts[metric_id] = self._metric_issue_counts.get(metric_id, 0) + 1
        snapshot.occurrence_count = self._metric_issue_counts[metric_id]

        if snapshot.severity == Severity.degraded:
            duration = now - self._metric_non_normal_since[metric_id]
            if duration >= ESCALATION_WINDOW_SECONDS and snapshot.trend == "worsening":
                snapshot.severity = Severity.critical
                snapshot.interpretation = f"{snapshot.label} on {self.channel} has stayed bad for {_format_duration(duration)} and is still getting worse. That usually means a real problem on the path, not just a brief hiccup."
                snapshot.recommendation = "Check the cable, port, or device that feeds this traffic right away."
        return snapshot

    def _simple_correlation_note(self, problem: str, support: str, *, confidence_boost: bool = False) -> str:
        if confidence_boost:
            return f"{problem} {support} This makes the alert more trustworthy."
        return f"{problem} {support}"

    def _maybe_resolve(self, metric_id: str, snapshot: MetricSnapshot) -> MetricSnapshot:
        now = self.last_packet_ts
        if snapshot.severity == Severity.normal:
            last_normal = self._metric_last_normal_at.get(metric_id, now)
            if now - last_normal >= RECOVERY_WINDOW_SECONDS:
                snapshot.resolved = True
        return snapshot

    def _make_alert(self, metric: MetricSnapshot) -> Optional[AlertEvent]:
        if metric.severity == Severity.normal:
            return None
        now = self.last_packet_ts
        existing = self.active_alerts.get(metric.metric_id)
        if existing is None:
            alert = AlertEvent(
                ts=now,
                channel=self.channel,
                metric_id=metric.metric_id,
                metric_label=metric.label,
                severity=metric.severity,
                interpretation=metric.interpretation,
                recommendation=metric.recommendation,
                current_value=metric.value,
                baseline_value=metric.baseline,
                confidence=metric.confidence,
                correlation_note=metric.correlation_note,
                occurrence_count=metric.occurrence_count,
                active=True,
                acknowledged=False,
                resolved=False,
                first_seen=now,
                last_seen=now,
                duration_seconds=metric.current_duration,
            )
            self.active_alerts[metric.metric_id] = alert
            self.alert_history.appendleft(alert)
            self.store.save_alert(alert)
            self.store.update_metric_counter(self.channel, metric.metric_id, metric.severity, metric.current_duration, alert.first_seen, alert.last_seen)
            return alert
        existing.last_seen = now
        existing.duration_seconds = metric.current_duration
        existing.severity = metric.severity
        existing.current_value = metric.value
        existing.baseline_value = metric.baseline
        existing.confidence = metric.confidence
        existing.occurrence_count = metric.occurrence_count
        existing.active = not existing.acknowledged
        if not existing.acknowledged:
            existing.interpretation = metric.interpretation
            existing.recommendation = metric.recommendation
            existing.correlation_note = metric.correlation_note
        self.store.update_latest_alert(
            self.channel,
            metric.metric_id,
            acknowledged=existing.acknowledged,
            resolved=existing.resolved,
            active=existing.active,
            duration_seconds=metric.current_duration,
            last_seen=now,
            severity=metric.severity.value,
            current_value=metric.value,
            baseline_value=metric.baseline,
            confidence=metric.confidence,
            interpretation=None if existing.acknowledged else metric.interpretation,
            recommendation=None if existing.acknowledged else metric.recommendation,
            correlation_note=None if existing.acknowledged else metric.correlation_note,
            occurrence_count=metric.occurrence_count,
        )
        return existing

    def acknowledge_alert(self, metric_id: str) -> bool:
        alert = self.active_alerts.get(metric_id)
        if not alert:
            return False
        alert.acknowledged = True
        alert.active = False
        alert.resolved = True
        self.store.update_latest_alert(self.channel, metric_id, acknowledged=True, resolved=True, active=False)
        return True

    def acknowledge_all_alerts(self, metric_ids: Iterable[str] | None = None) -> int:
        with self._locked("acknowledge_all_alerts"):
            if metric_ids is None:
                candidates = list(self.active_alerts.items())
            else:
                requested = {metric_id for metric_id in metric_ids}
                candidates = [(metric_id, self.active_alerts[metric_id]) for metric_id in requested if metric_id in self.active_alerts]

            acknowledged = 0
            for metric_id, alert in candidates:
                if alert.acknowledged:
                    continue
                alert.acknowledged = True
                alert.active = False
                alert.resolved = True
                self.store.update_latest_alert(self.channel, metric_id, acknowledged=True, resolved=True, active=False)
                acknowledged += 1
            return acknowledged

    def _metric_arp_ghost(self, now: float) -> tuple[MetricSnapshot, list[dict]]:
        history: list[dict] = []
        affected_targets: list[str] = []
        worst = Severity.normal
        label = "ARP Ghost-Target Repeat Rate"
        metric_id = "arp_ghost_target_repeat"
        current_value = 0.0
        current_baseline = 0.0
        interpretation = "No ARP ghost activity detected."
        recommendation = "No action needed."
        confidence = 72

        for target, data in self.arp_targets.items():
            requests = data["requests"]
            while requests and requests[0] < now - 600:
                requests.popleft()
            last_minute = sum(1 for ts in requests if ts >= now - 60)
            current_rate = float(last_minute)
            baseline_id = f"arp_ghost:{target}"
            learned_baseline, learned_stddev, samples, reliable = self._baseline_profile(baseline_id, max(1.0, current_rate or 1.0))
            multiplier = self._adaptive_multiplier(samples)
            baseline = max(1.0, learned_baseline)
            replies_seen = bool(data["reply_seen"])
            severity = Severity.normal
            if current_rate >= max(baseline * 3.0, baseline * (multiplier + 1.0)) and not replies_seen:
                severity = Severity.critical
            elif current_rate > baseline * 1.5:
                severity = Severity.advisory
            if _severity_rank(severity) > _severity_rank(worst):
                worst = severity
                current_value = current_rate
                current_baseline = baseline
                affected_targets.append(target)
                confidence = 70
            history.append({"ts": now, "target_ip": target, "target_name": self._resolve_name(target), "current_rate": current_rate, "baseline": baseline, "severity": severity.value})
            self._learn_baseline(baseline_id, current_rate, severity, allow_advisory=not reliable)

        scope, scope_count = self._affected_scope(affected_targets)
        if scope == "single":
            target_label = self._ip_label(affected_targets[0])
            interpretation = f"The target device {target_label} is not answering ARP or network requests."
            recommendation = "Check that device's power, cable, and switch port first. If it was recently moved or replaced, confirm the IP is still assigned to the right device."
        elif scope == "multiple":
            target_list = self._compact_labels(self._ip_label(target) for target in affected_targets[:3])
            suffix = f" Affected targets include {target_list}." if target_list else ""
            interpretation = f"Multiple targets are unreachable at the same time.{suffix} That usually means the shared switch, uplink, or segment is the problem, not each device separately."
            recommendation = "Check the shared switch, uplink, or segment first, then verify the affected IPs after the shared path is healthy."

        snapshot = self._build_metric(metric_id, label, current_value, current_baseline, worst, interpretation, recommendation, confidence, trend=self._trend(metric_id, current_value))
        return self._maybe_resolve(metric_id, self._escalate_if_needed(metric_id, snapshot)), history

    def _metric_gratuitous_arp(self, now: float) -> tuple[MetricSnapshot, list[dict]]:
        metric_id = "gratuitous_arp"
        label = "Gratuitous ARP Events"
        worst = Severity.normal
        current_value = 0
        current_baseline = 0
        interpretation = "No gratuitous ARP events observed."
        recommendation = "No action needed."
        confidence = 75
        history: list[dict] = []
        affected_devices: list[str] = []
        for ip, events in self.gratuitous_arp.items():
            while events and events[0] < now - 1800:
                events.popleft()
            count = len(events)
            baseline_id = f"gratuitous_arp:{ip}"
            learned_baseline, learned_stddev, samples, reliable = self._baseline_profile(baseline_id, float(count))
            multiplier = self._adaptive_multiplier(samples)
            baseline = max(0.0, learned_baseline)
            if count >= 3:
                severity = Severity.degraded
            elif count >= 1:
                severity = Severity.advisory
            else:
                severity = Severity.normal
            if reliable and count > baseline + max(1.0, learned_stddev * multiplier):
                severity = Severity.degraded if count < baseline + max(3.0, learned_stddev * (multiplier + 1.0)) else Severity.critical
            if _severity_rank(severity) > _severity_rank(worst):
                worst = severity
                current_value = count
                affected_devices.append(ip)
            self._learn_baseline(baseline_id, float(count), severity, allow_advisory=not reliable)
            history.append({"ts": now, "device": ip, "device_name": self._resolve_name(ip), "count": count, "severity": severity.value})

        scope, _ = self._affected_scope(affected_devices)
        if scope == "single":
            if current_value <= 1:
                interpretation = "This device sent a single gratuitous ARP, which is often normal when it boots or changes links."
                recommendation = "No action is needed unless it repeats."
            else:
                ip = affected_devices[0]
                ip_label = self._ip_label(ip)
                interpretation = f"This device {ip_label} is rejoining the network repeatedly."
                recommendation = "Check the device power, cable seating, and network adapter first. Repeats often mean a loose connector, brownout, or NIC/driver fault."
        elif scope == "multiple":
            device_list = self._compact_labels(self._ip_label(device) for device in affected_devices[:3])
            suffix = f" Affected devices include {device_list}." if device_list else ""
            interpretation = f"Several devices are announcing themselves repeatedly.{suffix} That usually means a shared network or power problem rather than a single device fault."
            recommendation = "Check the shared switch, uplink, or power source that those devices have in common."

        snapshot = self._build_metric(metric_id, label, current_value, current_baseline, worst, interpretation, recommendation, confidence, trend=self._trend(metric_id, float(current_value)))
        return self._maybe_resolve(metric_id, self._escalate_if_needed(metric_id, snapshot)), history

    def _metric_heartbeat(self, now: float) -> tuple[MetricSnapshot, list[dict]]:
        metric_id = "switch_heartbeat"
        label = "Switch Heartbeat Timing"
        worst = Severity.normal
        current_value = 0
        current_baseline = 0
        interpretation = "No switch heartbeat timing issues detected."
        recommendation = "No action needed."
        confidence = 85
        rows: list[dict] = []
        affected_devices: list[str] = []
        samples = 0
        reliable = False
        for (device_mac, protocol), state in self.heartbeat_states.items():
            gap = now - state.last_seen
            baseline_id = f"heartbeat:{device_mac}:{protocol}"
            learned_baseline, learned_stddev, samples, reliable = self._baseline_profile(baseline_id, state.baseline_interval or (median(state.intervals) if state.intervals else 0.0))
            baseline = learned_baseline or state.baseline_interval or (median(state.intervals) if state.intervals else 0.0)
            if samples < 5:
                severity = Severity.normal
            elif protocol == "STP" and gap > 10:
                severity = Severity.critical
            elif baseline > 0 and gap > baseline * 6:
                severity = Severity.critical
            elif baseline > 0 and gap > baseline * 3:
                severity = Severity.degraded
            elif baseline > 0 and gap > baseline * 1.5:
                severity = Severity.advisory
            else:
                severity = Severity.normal
            rows.append({"ts": now, "mac": device_mac, "device_name": self._resolve_name(device_mac, device_mac), "protocol": protocol, "gap_seconds": gap, "baseline_seconds": baseline, "severity": severity.value})
            if _severity_rank(severity) > _severity_rank(worst):
                worst = severity
                current_value = gap
                current_baseline = baseline
                affected_devices.append(device_mac)
                confidence = 55 if samples < 5 and not reliable else 85
            if baseline > 0 and samples >= 5:
                self._learn_baseline(baseline_id, gap if severity == Severity.normal else baseline, severity, allow_advisory=not reliable)

        scope, _ = self._affected_scope(affected_devices)
        if scope == "single":
            device_mac = affected_devices[0]
            display_name = self._resolve_name(device_mac, device_mac)
            interpretation = f"One device ({display_name}) has stopped sending heartbeat messages for {_format_duration(current_value)}."
            recommendation = "Check this device's port, confirm the link LED is on, reseat the cable, or try a different port or cable."
        elif scope == "multiple":
            device_list = self._compact_labels(self._resolve_name(device, device) for device in affected_devices[:3])
            suffix = f" Affected devices include {device_list}." if device_list else ""
            interpretation = f"Multiple devices lost heartbeat at the same time.{suffix} That usually means the switch itself rebooted, lost power, or is overloaded."
            recommendation = "Check the switch directly, its power, and any shared uplink or backplane issue before checking individual cables."
        elif samples < 5 and not reliable:
            interpretation = "This heartbeat pattern is still being learned, so the dashboard is being cautious for now."
            recommendation = "Keep collecting data until the normal interval becomes stable."

        snapshot = self._build_metric(metric_id, label, current_value, current_baseline, worst, interpretation, recommendation, confidence, trend=self._trend(metric_id, float(current_value)))
        return self._maybe_resolve(metric_id, self._escalate_if_needed(metric_id, snapshot)), rows

    def _metric_stp_tc(self, now: float) -> tuple[MetricSnapshot, list[dict]]:
        metric_id = "stp_topology_changes"
        label = "STP Topology-Change Rate"
        recent_hour = [ts for ts in self.stp_tc_times if ts >= now - 3600]
        recent_5m = [ts for ts in self.stp_tc_times if ts >= now - 300]
        count = len(recent_hour)
        baseline_id = "stp_topology_changes"
        learned_baseline, learned_stddev, samples, reliable = self._baseline_profile(baseline_id, float(count))
        baseline = max(0.0, learned_baseline)
        adaptive_limit = max(2.0, baseline + learned_stddev * self._adaptive_multiplier(samples))
        if len(recent_5m) >= 3 or count > max(10, adaptive_limit * 2.5):
            severity = Severity.critical
        elif count >= max(4, adaptive_limit * 1.6):
            severity = Severity.degraded
        elif count >= max(2, adaptive_limit * 0.8):
            severity = Severity.advisory
        else:
            severity = Severity.normal
        if count <= 1:
            interpretation = "A single topology change was seen. This is usually a brief reboot or a short drop and is not a concern unless it keeps happening."
            recommendation = "No action is needed unless the change repeats."
        else:
            recent_scope, _ = self._affected_scope(str(ts) for ts in recent_5m)
            if recent_scope == "single" or len(recent_5m) >= 3:
                interpretation = "Repeated topology changes are happening. That usually means one port is flapping and the link is going up and down."
                recommendation = "Check the most recently changed link, cable, and port for a loose connector or failing hardware."
            else:
                interpretation = f"{count} topology-change events were seen in the last hour. Something on the segment is unstable."
                recommendation = "Inspect the involved switch ports and physical connections."
        self._learn_baseline(baseline_id, float(count), severity, allow_advisory=not reliable)
        snapshot = self._build_metric(metric_id, label, count, baseline, severity, interpretation, recommendation, 80, trend=self._trend(metric_id, float(count)))
        rows = [{"ts": ts, "count": 1, "window": "hour"} for ts in recent_hour]
        return self._maybe_resolve(metric_id, self._escalate_if_needed(metric_id, snapshot)), rows

    def _metric_stp_root(self, now: float) -> tuple[MetricSnapshot, list[dict]]:
        metric_id = "stp_root_path"
        label = "STP Root / Path Cost Tracking"
        severity = Severity.normal
        current_value = self.stp_path_cost
        baseline = self._display_baselines.get(metric_id, self.stp_path_cost)
        interpretation = "STP root and path cost are stable."
        recommendation = "No action needed."
        if self.stp_root_mac and self._display_baselines.get("stp_root_mac") and self._display_baselines["stp_root_mac"] != self.stp_root_mac:
            severity = Severity.critical
            interpretation = "The switch acting as the network root has changed."
            recommendation = "Check whether the previous root switch lost power or rebooted, then review the switch logs."
        elif self.stp_path_cost and self._display_baselines.get("stp_path_cost") and self._display_baselines["stp_path_cost"] != self.stp_path_cost:
            severity = Severity.degraded
            interpretation = "A backup link has taken over from the primary path."
            recommendation = "This can be normal failover, but confirm the primary uplink is still up and healthy."
        if "stp_root_mac" not in self._display_baselines and self.stp_root_mac:
            self._display_baselines["stp_root_mac"] = self.stp_root_mac
        if "stp_path_cost" not in self._display_baselines and self.stp_path_cost:
            self._display_baselines["stp_path_cost"] = self.stp_path_cost
        self._learn_baseline(metric_id, float(current_value), severity)
        snapshot = self._build_metric(metric_id, label, current_value, baseline, severity, interpretation, recommendation, 75, trend=self._trend(metric_id, float(current_value)))
        rows = [{"ts": now, "root_mac": self.stp_root_mac, "path_cost": self.stp_path_cost, "severity": severity.value}]
        return self._maybe_resolve(metric_id, self._escalate_if_needed(metric_id, snapshot)), rows

    def _metric_jitter_and_loss(self, now: float) -> tuple[list[MetricSnapshot], list[dict], list[dict]]:
        metrics: list[MetricSnapshot] = []
        jitter_rows: list[dict] = []
        loss_rows: list[dict] = []
        active_flows = 0
        monitored = [flow for flow in self.flow_states.values() if flow.monitored]
        for flow in monitored:
            active_flows += 1
            flow_label = self._flow_label(flow)
            repeat_count = self._metric_issue_counts.get(f"jitter:{flow.flow_id}", 0)
            occurrence_count = repeat_count + 1
            recurring_warning = occurrence_count >= 3
            strong_warning = occurrence_count >= 5
            timestamps = list(flow.timestamps)
            recent_cutoff = now - 60
            recent_intervals = [
                t2 - t1
                for t1, t2 in zip(timestamps, timestamps[1:])
                if t2 >= recent_cutoff
            ]
            jitter = float(np.std(recent_intervals)) if recent_intervals else 0.0
            jitter_id = f"jitter:{flow.flow_id}"
            loss_id = f"loss:{flow.flow_id}"
            learned_baseline, _, samples, reliable = self._baseline_profile(jitter_id, flow.baseline_jitter or max(0.001, jitter))
            baseline = max(0.001, learned_baseline or flow.baseline_jitter or jitter or 0.001)
            severity = Severity.normal
            interpretation = f"{flow_label} is stable."
            recommendation = "No action needed."
            confidence = 60
            if flow.expected_interval > 0:
                expected_count = max(1.0, 60.0 / flow.expected_interval)
                actual_count = sum(1 for ts in flow.timestamps if ts >= now - 60)
                loss_pct = max(0.0, (expected_count - actual_count) / expected_count * 100.0)
            else:
                loss_pct = 0.0
                expected_count = 0.0
                actual_count = 0.0
            loss_baseline, _, loss_samples, loss_reliable = self._baseline_profile(loss_id, loss_pct)
            if samples < 5:
                severity = Severity.normal
            elif jitter > baseline * 8.0 or actual_count == 0:
                severity = Severity.critical
            elif jitter > baseline * 4.0 or loss_pct > 20:
                severity = Severity.degraded
            elif jitter > baseline * 2.0 or loss_pct >= 1:
                severity = Severity.advisory

            if severity == Severity.normal:
                if samples < 5 and not reliable:
                    interpretation = "This flow is still learning what normal looks like, so the timing numbers are not reliable yet."
                    recommendation = "Keep collecting a few more samples before acting on it."
                    confidence = 55
            elif severity == Severity.advisory:
                if loss_pct >= 1:
                    interpretation = f"{flow_label} is a little uneven and is also dropping packets."
                    recommendation = "Check the sender's cable and switch port first."
                else:
                    interpretation = f"{flow_label} is getting a bit irregular."
                    recommendation = "Check the sender's cable and switch port first."
                confidence = 70
            elif severity == Severity.degraded:
                if loss_pct >= 1:
                    interpretation = f"{flow_label} is losing packets and arriving unevenly at the same time."
                    recommendation = "Check the sender and its switch port first. If this same flow keeps showing the problem, treat it as a persistent link issue."
                else:
                    interpretation = f"{flow_label} is showing stronger timing instability than usual."
                    recommendation = "Check the sender and its switch port first. If it keeps coming back, it is likely the link rather than a one-off blip."
                confidence = 65
            elif severity == Severity.critical:
                if loss_pct >= 1:
                    interpretation = f"{flow_label} is badly unstable and is dropping packets."
                    recommendation = "This has been repeating for a while. Check the sender and its switch port right away."
                else:
                    interpretation = f"{flow_label} is badly unstable and is no longer keeping up with its expected timing."
                    recommendation = "This has been repeating for a while. Check the sender and its switch port right away."
                confidence = 70
            display_jitter_ms = jitter * 1000.0
            display_baseline_ms = baseline * 1000.0
            snap = self._build_metric(
                jitter_id,
                "Flow Timing",
                display_jitter_ms,
                display_baseline_ms,
                severity,
                interpretation,
                recommendation,
                confidence,
                trend=self._trend(jitter_id, display_jitter_ms),
            )
            metrics.append(self._maybe_resolve(jitter_id, self._escalate_if_needed(jitter_id, snap)))
            jitter_rows.append({
                "ts": now,
                "flow_id": flow.flow_id,
                "flow_name": f"{self._resolve_name(flow.src_ip, flow.src_ip)} -> {self._resolve_name(flow.dst_ip, flow.dst_ip)}",
                "jitter_ms": display_jitter_ms,
                "baseline_ms": display_baseline_ms,
                "severity": severity.value,
            })
            loss_rows.append({
                "ts": now,
                "flow_id": flow.flow_id,
                "flow_name": f"{self._resolve_name(flow.src_ip, flow.src_ip)} -> {self._resolve_name(flow.dst_ip, flow.dst_ip)}",
                "loss_pct": loss_pct,
                "expected": expected_count,
                "actual": actual_count,
                "severity": severity.value,
            })
            self._learn_baseline(jitter_id, jitter, severity, allow_advisory=not reliable)
            self._learn_baseline(loss_id, loss_pct, severity, allow_advisory=not loss_reliable)
        if not monitored:
            metrics.append(self._build_metric("jitter:no_flows", "Flow Timing", 0.0, 0.0, Severity.normal, "No periodic flows have been identified yet.", "No action needed.", 0))
            metrics.append(self._build_metric("loss:no_flows", "Packet Loss Estimation", 0.0, 0.0, Severity.normal, "No monitored periodic flows yet.", "No action needed.", 0))
        else:
            loss_values = [r["loss_pct"] for r in loss_rows]
            loss_value = float(max(loss_values) if loss_values else 0.0)
            problem_loss_rows = [row for row in loss_rows if row["severity"] != Severity.normal.value or row["loss_pct"] >= 1]
            problem_loss_flow_ids = [row["flow_id"] for row in problem_loss_rows]
            problem_loss_flow_names = [row["flow_name"] for row in problem_loss_rows]
            problem_scope, problem_count = self._affected_scope(problem_loss_flow_ids)
            jitter_problem_flow_ids = {row["flow_id"] for row in jitter_rows if row["severity"] != Severity.normal.value}
            loss_metric = self._build_metric(
                "packet_loss_estimation",
                "Packet Loss Estimation",
                loss_value,
                0.0,
                Severity.normal if not loss_values else self._severity_from_thresholds(loss_value, 1.0, 5.0, 20.0),
                "Packet loss is being checked against the expected flow pattern.",
                "Check the sender's cable and switch port first.",
                70,
                trend=self._trend("packet_loss_estimation", loss_value),
                correlation_note="This matches the timing problem on the same flow, so it points to one bad link and makes the alert stronger.",
            )
            if problem_scope == "single" and problem_loss_flow_names:
                flow_label = problem_loss_flow_names[0]
                loss_metric.interpretation = f"Packet loss is showing up on {flow_label}."
                if problem_loss_flow_ids[0] in jitter_problem_flow_ids:
                    loss_metric.interpretation += " The same flow is also timing unevenly."
                    loss_metric.correlation_note = "The timing problem and packet loss are on the same flow, so this is one path issue. That makes the alert more trustworthy."
                loss_metric.recommendation = "Check the sender's cable and switch port first."
            elif problem_scope == "multiple" and problem_loss_flow_names:
                flow_list = self._compact_labels(problem_loss_flow_names[:3])
                loss_metric.interpretation = f"Several monitored flows are losing packets at the same time. Affected flows include {flow_list}."
                loss_metric.correlation_note = "Several flows are affected together, which points to one shared link. That makes the shared-path diagnosis stronger."
                loss_metric.recommendation = "Check the shared link those flows use first."
            if loss_metric.occurrence_count >= 4:
                loss_metric.correlation_note = (loss_metric.correlation_note + " " if loss_metric.correlation_note else "") + "It has repeated enough times to be a stronger warning, not just a brief glitch."
            metrics.append(self._maybe_resolve("packet_loss_estimation", self._escalate_if_needed("packet_loss_estimation", loss_metric)))
            self._learn_baseline("packet_loss_estimation", loss_value, loss_metric.severity)
        return metrics, jitter_rows, loss_rows

    def _metric_traffic_ratio_and_burst(self, now: float) -> tuple[list[MetricSnapshot], list[dict], list[dict]]:
        pps = self._rolling_packets_per_sec(now)
        bps = self._rolling_bytes_per_sec(now)
        self.metric_history["pps"].append({"ts": now, "value": pps})
        self.metric_history["bps"].append({"ts": now, "value": bps})
        pps_baseline, pps_stddev, pps_samples, pps_reliable = self._baseline_profile("pps", float(pps))
        bps_baseline, bps_stddev, bps_samples, bps_reliable = self._baseline_profile("bps", float(bps))
        pps_values = [item["value"] for item in self.metric_history["pps"]][-min(len(self.metric_history["pps"]), 600):]
        bps_values = [item["value"] for item in self.metric_history["bps"]][-min(len(self.metric_history["bps"]), 600):]
        pps_baseline_mean = float(median(pps_values)) if pps_values else pps_baseline
        pps_baseline_std = float(pstdev(pps_values)) if len(pps_values) > 1 else pps_stddev
        bps_baseline_mean = float(median(bps_values)) if bps_values else bps_baseline
        bps_baseline_std = float(pstdev(bps_values)) if len(bps_values) > 1 else bps_stddev
        pps_limit = pps_baseline_mean + (3.0 * pps_baseline_std)
        bps_limit = bps_baseline_mean + (3.0 * bps_baseline_std)
        pps_history = [item["value"] for item in self.metric_history["pps"]][-120:]
        bps_history = [item["value"] for item in self.metric_history["bps"]][-120:]
        pps_recent = float(median(pps_history[:-1][-10:])) if len(pps_history) > 1 else pps
        bps_recent = float(median(bps_history[:-1][-10:])) if len(bps_history) > 1 else bps
        pps_burst = bool(pps_values) and pps > pps_limit
        bps_burst = bool(bps_values) and bps > bps_limit
        time_since_packet = now - self.last_packet_ts
        startup_window = now - self.started_at <= 120.0
        recent_devices = self._recent_devices(now, 60.0)
        recent_device_labels = [self._device_label(device) for device in recent_devices]
        recent_device_scope, recent_device_count = self._affected_scope(device.device_id for device in recent_devices)
        extreme_high = bps_burst or pps_burst or (
            bps > max(bps_limit * 1.5, bps_baseline_mean * 4.0 if bps_baseline_mean > 0 else 0.0)
            and pps > max(pps_limit * 1.25, pps_baseline_mean * 3.0 if pps_baseline_mean > 0 else 0.0)
        )
        very_low_bps = bps_baseline_mean > 0 and bps <= max(1.0, bps_baseline_mean * 0.15)
        very_low_pps = pps_baseline_mean > 0 and pps <= max(1.0, pps_baseline_mean * 0.15)
        extreme_low = (
            (startup_window and self.total_packets == 0 and time_since_packet >= 15.0)
            or (self.total_packets > 0 and time_since_packet >= 20.0 and very_low_bps and very_low_pps)
            or (recent_device_count >= 3 and very_low_bps and very_low_pps and (bps_recent > bps * 4.0 or pps_recent > pps * 4.0))
        )
        burst = extreme_high or extreme_low or bps_burst
        burst_severity = Severity.critical if extreme_high or extreme_low else (Severity.advisory if burst else Severity.normal)
        if burst and self.stp_tc_times and now - self.stp_tc_times[-1] <= 120 and not extreme_low:
            burst_severity = Severity.degraded
        if extreme_low:
            if recent_device_scope == "single" and recent_device_labels:
                burst_interpretation = f"Traffic from {recent_device_labels[0]} has fallen off sharply."
            elif recent_device_count >= 3:
                burst_interpretation = f"Traffic has dropped across several recently active devices."
            else:
                burst_interpretation = "Traffic has fallen to almost nothing."
            if startup_window and self.total_packets == 0 and time_since_packet >= 15.0:
                burst_recommendation = "Check immediately. No traffic has arrived since capture started, so the collector, uplink, or source devices may not be sending data."
            elif self.total_packets > 0 and time_since_packet >= 20.0:
                burst_recommendation = "Check immediately. Data stopped coming from a lot of devices or the path is no longer forwarding traffic."
            else:
                burst_recommendation = "Check immediately. The active devices, uplink, and collector path may have stalled, and the network could be losing visibility fast."
        elif burst_severity == Severity.degraded:
            burst_interpretation = "A burst started right after a topology change."
            burst_recommendation = "Check the recently changed link and the devices that depend on it. The traffic likely moved to a new path or is catching up after the change."
        elif extreme_high and pps_burst and bps_burst:
            if recent_device_scope == "single" and recent_device_labels:
                burst_interpretation = f"{recent_device_labels[0]} is sending both more data and more packets than usual."
                burst_recommendation = f"Check the source device and uplink immediately. Very high traffic can overload the link or collector, and you may start losing data values."
            else:
                burst_interpretation = "Both the size of traffic and the number of packets are far above normal. That usually means the segment is overloaded or a flood is in progress."
                burst_recommendation = "Check the active devices and the switch path they share immediately. Very high traffic can overload the link or collector, and the data stream may start dropping values."
        elif extreme_high and bps_burst:
            if recent_device_scope == "single" and recent_device_labels:
                burst_interpretation = f"{recent_device_labels[0]} is sending larger-than-normal payloads."
                burst_recommendation = f"Check the source device and uplink immediately. The link may be overloaded, and you may start losing data values."
            else:
                burst_interpretation = "Traffic volume is far above normal because some active device or devices are sending much larger payloads."
                burst_recommendation = "Check the active devices first. The link may be overloaded, and the collector could start missing values."
        elif extreme_high and pps_burst:
            if recent_device_scope == "single" and recent_device_labels:
                burst_interpretation = f"{recent_device_labels[0]} is sending a flood of small packets."
                burst_recommendation = f"Check the source device and its switch port immediately. Very high packet rates can overload the path and you may lose data values."
            else:
                burst_interpretation = "A flood of small packets is hitting the network."
                burst_recommendation = "Check the active devices and switch path immediately. Very high packet rates can overload the path and you may lose data values."
        else:
            burst_interpretation = "Traffic is elevated compared with the normal baseline."
            burst_recommendation = "Check whether the higher traffic is expected or if one of the recently active devices has started sending more than usual. The baseline only adjusts from quiet windows, not burst windows."
        burst_metric = self._build_metric("traffic_burst", "Traffic Burst / Drop", bps, bps_baseline_mean, burst_severity, burst_interpretation, burst_recommendation, 80, trend=self._trend("traffic_burst", float(bps)))
        if not burst and not extreme_low and not extreme_high:
            self._learn_baseline("pps", float(pps), burst_severity, allow_advisory=not pps_reliable, weight=0.08)
            self._learn_baseline("bps", float(bps), burst_severity, allow_advisory=not bps_reliable, weight=0.08)

        ratio = (self.total_packets if self.total_packets else 0) / max(1, len([x for x in self.packet_times if x >= now - 60]))
        broadcast_count = len([ts for ts in self.broadcast_times if ts >= now - 60]) + len([ts for ts in self.multicast_times if ts >= now - 60])
        unicast_count = max(1, len([ts for ts in self.packet_times if ts >= now - 60]) - broadcast_count)
        ratio_value = broadcast_count / unicast_count
        ratio_baseline_value, ratio_stddev, ratio_samples, ratio_reliable = self._baseline_profile("ratio", float(ratio_value))
        ratio_history = [item["value"] for item in self.metric_history["ratio"]][-600:]
        ratio_baseline = float(mean(ratio_history)) if ratio_history else ratio_baseline_value
        ratio_severity = Severity.normal
        ratio_limit = ratio_baseline * 2.5 if ratio_baseline > 0 else 0.0
        if ratio_limit > 0 and ratio_value > ratio_limit * 1.5:
            ratio_severity = Severity.degraded if not self.stp_tc_times or now - self.stp_tc_times[-1] > 300 else Severity.advisory
        elif ratio_limit > 0 and ratio_value > ratio_limit:
            ratio_severity = Severity.advisory
        if ratio_value <= max(1.0, ratio_baseline * 1.2):
            ratio_interpretation = "Broadcast traffic is close to the normal baseline."
            ratio_recommendation = "No action is needed."
        else:
            if recent_device_scope == "single" and recent_device_labels:
                ratio_interpretation = f"Broadcast traffic looks concentrated around {recent_device_labels[0]}."
                ratio_recommendation = f"{recent_device_labels[0]} may have a failing NIC or misconfigured interface flooding broadcasts. Isolate it and test it alone."
            else:
                affected_devices = self._compact_labels(recent_device_labels[:3])
                if affected_devices:
                    ratio_interpretation = f"Broadcast traffic is spread across several active devices, including {affected_devices}."
                else:
                    ratio_interpretation = "Broadcast traffic looks widespread across the network."
                ratio_recommendation = "Check the location where it is connected. Ensure reply access is avaliable. Most likely a physical loop. Check for a second or duplicate cable run between switches that should not both be connected."
        ratio_metric = self._build_metric("broadcast_unicast_ratio", "Broadcast-to-Unicast Ratio", ratio_value, ratio_baseline, ratio_severity, ratio_interpretation, ratio_recommendation, 55, trend=self._trend("broadcast_unicast_ratio", ratio_value))
        self._learn_baseline("ratio", ratio_value, ratio_severity, allow_advisory=not ratio_reliable)

        burst_series = [{
            "ts": now,
            "pps": pps,
            "bps": bps,
            "pps_baseline_mean": pps_baseline_mean,
            "pps_baseline_std": pps_baseline_std,
            "bps_baseline_mean": bps_baseline_mean,
            "bps_baseline_std": bps_baseline_std,
            "pps_burst": pps_burst,
            "bps_burst": bps_burst,
            "burst": burst,
            "severity": burst_severity.value,
        }]
        ratio_series = [{"ts": now, "ratio": ratio_value, "baseline": ratio_baseline, "severity": ratio_severity.value}]
        return [self._maybe_resolve("traffic_burst", self._escalate_if_needed("traffic_burst", burst_metric)), self._maybe_resolve("broadcast_unicast_ratio", self._escalate_if_needed("broadcast_unicast_ratio", ratio_metric))], burst_series, ratio_series

    def _metric_device_silence(self, now: float) -> tuple[MetricSnapshot, list[dict]]:
        metric_id = "device_silence"
        label = "Device Silence / Inactivity"
        worst = Severity.normal
        current_value = 0
        baseline = 0
        interpretation = "No device inactivity issue detected."
        recommendation = "No action needed."
        rows: list[dict] = []
        for device in self.device_states.values():
            gap = now - device.last_seen
            device.silent = gap > 60
            if not device.expected_interval and len(device.intervals) >= 5:
                device.expected_interval = float(median(device.intervals))
            typical = device.expected_interval or 1.0
            silence_id = f"silence:{device.device_id}"
            learned_baseline, learned_stddev, samples, reliable = self._baseline_profile(silence_id, typical)
            typical = max(1.0, learned_baseline or typical)
            if samples < 5 and not reliable:
                severity = Severity.normal
            elif gap > 300:
                severity = Severity.critical
            elif gap > 60:
                severity = Severity.degraded
            elif gap > max(typical * 2.0, typical + 5.0):
                severity = Severity.advisory
            else:
                severity = Severity.normal
            rows.append({"ts": now, "device_id": device.device_id, "last_seen_gap": gap, "typical_interval": typical, "severity": severity.value})
            if _severity_rank(severity) > _severity_rank(worst):
                worst = severity
                current_value = gap
                baseline = typical
                if samples < 5 and not reliable:
                    interpretation = f"{device.src_ip or device.src_mac} is still learning its normal silence pattern."
                    recommendation = "Keep watching until the baseline settles."
                else:
                    interpretation = f"{device.src_ip or device.src_mac} has gone quiet for {_format_duration(gap)}."
                    recommendation = "Check power and the link light on this specific device. This is the fastest thing to verify when something goes silent."
            if samples >= 5:
                self._learn_baseline(silence_id, gap if severity == Severity.normal else typical, severity, allow_advisory=not reliable)
        metric = self._build_metric(metric_id, label, current_value, baseline, worst, interpretation, recommendation, 75, trend=self._trend(metric_id, float(current_value)))
        return self._maybe_resolve(metric_id, self._escalate_if_needed(metric_id, metric)), rows

    def _heartbeat_panel(self, now: float) -> list[dict]:
        rows = []
        for state in self.heartbeat_states.values():
            gap = now - state.last_seen
            rows.append({"device_mac": state.device_mac, "protocol": state.protocol, "last_seen_seconds_ago": gap, "baseline_interval": state.baseline_interval})
        return rows

    def _timeline(self, metrics: list[MetricSnapshot], now: float) -> list[dict]:
        return [
            {"metric": metric.label, "metric_id": metric.metric_id, "severity": metric.severity.value, "duration_seconds": metric.current_duration, "timestamp": now}
            for metric in metrics
            if not metric.metric_id.startswith("jitter:")
        ]

    def tick(self, now: Optional[float] = None) -> ChannelSnapshot:
        pending_baseline_saves: dict[str, tuple[str, dict]] = {}
        snapshot_to_save: ChannelSnapshot | None = None
        with self._locked("tick"):
            now = float(now if now is not None else time.time())
            self.last_tick_ts = now
            pps = self._rolling_packets_per_sec(now)
            bps = self._rolling_bytes_per_sec(now)
            self.series_buffers["traffic"].append({"ts": now, "pps": pps, "bps": bps})
            active_devices = sum(1 for device in self.device_states.values() if now - device.last_seen <= 12)
            active_flows = sum(1 for flow in self.flow_states.values() if now - flow.last_seen <= 60)

            metrics: list[MetricSnapshot] = []
            histories: dict[str, list[dict]] = {}
            snap, history = self._metric_arp_ghost(now)
            metrics.append(snap)
            histories["arp_series"] = history

            snap, history = self._metric_gratuitous_arp(now)
            metrics.append(snap)
            histories["gratuitous"] = history

            snap, history = self._metric_heartbeat(now)
            metrics.append(snap)
            histories["heartbeat_series"] = history

            snap, history = self._metric_stp_tc(now)
            metrics.append(snap)
            histories["stp_series"] = history

            snap, history = self._metric_stp_root(now)
            metrics.append(snap)
            histories["stp_root_series"] = history

            jitter_metrics, jitter_series, loss_series = self._metric_jitter_and_loss(now)
            metrics.extend(jitter_metrics)
            histories["jitter_series"] = jitter_series
            histories["loss_series"] = loss_series

            ratio_metrics, burst_series, ratio_series = self._metric_traffic_ratio_and_burst(now)
            metrics.extend(ratio_metrics)
            histories["burst_series"] = burst_series
            histories["ratio_series"] = ratio_series

            silence_metric, silence_rows = self._metric_device_silence(now)
            metrics.append(silence_metric)
            histories["silence_rows"] = silence_rows

            for row in histories.get("jitter_series", []):
                self.series_buffers["jitter"].append(row)
            for row in histories.get("loss_series", []):
                self.series_buffers["loss"].append(row)
            for row in histories.get("burst_series", []):
                self.series_buffers["burst"].append(row)
            for row in histories.get("ratio_series", []):
                self.series_buffers["ratio"].append(row)
            for row in histories.get("heartbeat_series", []):
                self.series_buffers["heartbeat"].append(row)
            for row in histories.get("stp_series", []):
                self.series_buffers["stp"].append(row)
            for row in histories.get("stp_root_series", []):
                self.series_buffers["stp_root"].append(row)
            for row in histories.get("arp_series", []):
                self.series_buffers["arp"].append(row)
            for row in histories.get("silence_rows", []):
                self.series_buffers["silence"].append(row)

            for metric in metrics:
                self.metric_history[metric.metric_id].append({"ts": now, "value": metric.value, "severity": metric.severity.value})
                if metric.severity != Severity.normal:
                    self.summary_counts[metric.severity.value] += 1
                metric.muted = self.is_alert_muted(metric.metric_id)
                if metric.muted:
                    existing = self.active_alerts.pop(metric.metric_id, None)
                    if existing is not None:
                        existing.active = False
                        existing.resolved = True
                        self.store.update_latest_alert(
                            self.channel,
                            metric.metric_id,
                            acknowledged=existing.acknowledged,
                            resolved=True,
                            active=False,
                            duration_seconds=metric.current_duration,
                            last_seen=now,
                        )
                    continue
                if metric.metric_id in self.active_alerts:
                    alert = self.active_alerts[metric.metric_id]
                    alert.last_seen = now
                    alert.duration_seconds = metric.current_duration
                    alert.severity = metric.severity
                    if not alert.acknowledged:
                        alert.interpretation = metric.interpretation
                        alert.recommendation = metric.recommendation
                        alert.correlation_note = metric.correlation_note
                    if metric.severity == Severity.normal and metric.resolved:
                        alert.resolved = True
                        alert.active = False
                        self.store.update_latest_alert(self.channel, metric.metric_id, resolved=True, active=False, duration_seconds=metric.current_duration, last_seen=now)
                        self.active_alerts.pop(metric.metric_id, None)
                else:
                    self._make_alert(metric)
                if metric.metric_id in self.active_alerts:
                    self.store.update_latest_alert(
                        self.channel,
                        metric.metric_id,
                        acknowledged=self.active_alerts[metric.metric_id].acknowledged,
                        resolved=self.active_alerts[metric.metric_id].resolved,
                        active=self.active_alerts[metric.metric_id].active,
                        duration_seconds=metric.current_duration,
                        last_seen=now,
                        severity=self.active_alerts[metric.metric_id].severity.value,
                        current_value=self.active_alerts[metric.metric_id].current_value,
                        baseline_value=self.active_alerts[metric.metric_id].baseline_value,
                        confidence=self.active_alerts[metric.metric_id].confidence,
                        interpretation=None if self.active_alerts[metric.metric_id].acknowledged else self.active_alerts[metric.metric_id].interpretation,
                        recommendation=None if self.active_alerts[metric.metric_id].acknowledged else self.active_alerts[metric.metric_id].recommendation,
                        correlation_note=None if self.active_alerts[metric.metric_id].acknowledged else self.active_alerts[metric.metric_id].correlation_note,
                    )

            live_alerts = [alert for alert in self.active_alerts.values() if alert.active and not alert.acknowledged]
            overall = _worst(*(alert.severity for alert in live_alerts)) if live_alerts else Severity.normal
            alert_counts = Counter(alert.severity.value for alert in live_alerts)

            history = list(self.series_buffers["traffic"])
            recent_devices = sorted(self.device_states.values(), key=lambda device: device.last_seen, reverse=True)[:100]
            recent_flows = sorted(self.flow_states.values(), key=lambda flow: flow.last_seen, reverse=True)[:100]
            snapshot = ChannelSnapshot(
                channel=self.channel,
                ts=now,
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                pps=pps,
                bps=bps,
                broadcast_packets=len([ts for ts in self.broadcast_times if ts >= now - WINDOW_SECONDS]),
                multicast_packets=len([ts for ts in self.multicast_times if ts >= now - WINDOW_SECONDS]),
                udp_packets=len([ts for ts in self.udp_times if ts >= now - WINDOW_SECONDS]),
                arp_packets=len([ts for ts in self.arp_times if ts >= now - WINDOW_SECONDS]),
                active_devices=active_devices,
                active_flows=active_flows,
                alert_counts=dict(alert_counts),
                overall_severity=overall,
                alert_mutes=self.get_alert_mutes(),
                metrics=metrics,
                alerts=live_alerts,
                history=history,
                jitter_series=list(self.series_buffers["jitter"]),
                loss_series=list(self.series_buffers["loss"]),
                burst_series=list(self.series_buffers["burst"]),
                ratio_series=list(self.series_buffers["ratio"]),
                heartbeat_series=self._heartbeat_panel(now),
                heartbeat_history=list(self.series_buffers["heartbeat"]),
                stp_series=list(self.series_buffers["stp"]),
                stp_root_series=list(self.series_buffers["stp_root"]),
                arp_series=list(self.series_buffers["arp"]),
                silence_series=list(self.series_buffers["silence"]),
                event_timeline=self._timeline(metrics, now),
                devices=[
                    {
                        "device_id": device.device_id,
                        "src_mac": device.src_mac,
                        "src_ip": device.src_ip,
                        "display_name": self._ip_label(device.src_ip) if device.src_ip else self._resolve_name(device.src_mac, device.device_id),
                        "last_seen": device.last_seen,
                        "packet_count": device.packet_count,
                        "byte_count": device.byte_count,
                        "expected_interval": device.expected_interval,
                        "avg_jitter_ms": device.avg_jitter_ms,
                        "max_jitter_ms": device.max_jitter_ms,
                        "silent": device.silent,
                    }
                    for device in recent_devices
                ],
                flows=[
                    {
                        "flow_id": flow.flow_id,
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "src_name": self._ip_label(flow.src_ip) if flow.src_ip else "",
                        "dst_name": self._ip_label(flow.dst_ip) if flow.dst_ip else "",
                        "src_port": flow.src_port,
                        "dst_port": flow.dst_port,
                        "expected_interval": flow.expected_interval,
                        "baseline_jitter": flow.baseline_jitter,
                        "baseline_loss": flow.baseline_loss,
                        "monitored": flow.monitored,
                        "last_seen": flow.last_seen,
                    }
                    for flow in recent_flows
                ],
                fault_banner=self.config.banner,
                source_mode=self.config.source_mode.value,
                source_name=self.config.uploaded_name or self.config.interface_name or "",
            )
            self.last_snapshot = snapshot
            if now - self._last_snapshot_save_ts >= 15.0:
                snapshot_to_save = ChannelSnapshot(
                    channel=self.channel,
                    ts=now,
                    total_packets=self.total_packets,
                    total_bytes=self.total_bytes,
                    pps=pps,
                    bps=bps,
                    broadcast_packets=snapshot.broadcast_packets,
                    multicast_packets=snapshot.multicast_packets,
                    udp_packets=snapshot.udp_packets,
                    arp_packets=snapshot.arp_packets,
                    active_devices=active_devices,
                    active_flows=active_flows,
                    alert_counts=dict(alert_counts),
                    overall_severity=overall,
                    fault_banner=self.config.banner,
                    source_mode=self.config.source_mode.value,
                    source_name=self.config.uploaded_name or self.config.interface_name or "",
                )
                self._last_snapshot_save_ts = now
            if self._pending_baseline_saves:
                pending_baseline_saves = self._pending_baseline_saves
                self._pending_baseline_saves = {}
        if snapshot_to_save is not None:
            try:
                self._log.debug("[%s] saving compact snapshot outside engine.lock", self.channel)
                self.store.save_snapshot(snapshot_to_save)
            except Exception:
                self._log.exception("[%s] failed to save compact snapshot", self.channel)
        for metric_id, (value, details) in pending_baseline_saves.items():
            try:
                self._log.debug("[%s] saving baseline %s outside engine.lock", self.channel, metric_id)
                self.store.save_baseline(self.channel, metric_id, value, details)
            except Exception:
                self._log.exception("[%s] failed to save baseline %s", self.channel, metric_id)
        return snapshot
