from __future__ import annotations

import asyncio
import logging
import queue
import socket
import threading
import time
from dataclasses import asdict, replace
from collections import deque
from pathlib import Path
from typing import Any, Callable, Optional

from .config import CHANNELS, PN, CN, UPLOAD_DIR
from .engine import ChannelEngine
from .models import ChannelConfig, FaultConfig, FaultType, PacketEvent, SourceMode
from .parser import iterate_pcap, normalize_packet
from .storage import SQLiteStore


LOGGER = logging.getLogger("backend.runtime")


def _interface_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    return (
        0 if item.get("preferred") else 1,
        0 if item.get("is_up") else 1,
        item.get("name", ""),
    )


def _resolve_capture_interface_name(interface_name: str | None) -> str:
    preferred = (interface_name or "").strip()
    if not preferred:
        return ""

    if preferred.startswith("\\Device\\NPF_"):
        return preferred

    try:
        from scapy.all import conf
    except Exception:
        return preferred

    iface = None
    for candidate in (preferred, preferred.lower()):
        try:
            iface = conf.ifaces.dev_from_name(candidate)
        except Exception:
            iface = None
        if iface is not None:
            break

    if iface is not None:
        return str(iface)

    try:
        from scapy.arch.windows import get_windows_if_list
    except Exception:
        return preferred

    target = preferred.lower()
    for item in get_windows_if_list():
        candidates = {
            str(item.get("name", "")).strip().lower(),
            str(item.get("description", "")).strip().lower(),
            str(item.get("guid", "")).strip().lower(),
        }
        ips = {str(ip).strip().lower() for ip in item.get("ips", [])}
        if target in candidates or target in ips:
            guid = str(item.get("guid", "")).strip()
            if guid:
                return f"\\Device\\NPF_{guid.strip('{}')}"
    return preferred


def list_live_interfaces() -> list[dict[str, Any]]:
    try:
        import psutil
    except Exception:
        psutil = None

    interfaces: list[dict[str, Any]] = []
    stats = psutil.net_if_stats() if psutil else {}
    addrs = psutil.net_if_addrs() if psutil else {}
    for name, stat in (stats or {}).items():
        if not name:
            continue
        iface_addrs = addrs.get(name, [])
        ipv4 = next((addr.address for addr in iface_addrs if getattr(addr, "family", None) == socket.AF_INET), "")
        ipv6 = next((addr.address for addr in iface_addrs if getattr(addr, "family", None) == socket.AF_INET6), "")
        mac = next((addr.address for addr in iface_addrs if getattr(addr, "family", None) not in {socket.AF_INET, socket.AF_INET6}), "")
        capture_name = _resolve_capture_interface_name(name)
        is_loopback = name.lower() in {"lo", "loopback"} or ipv4.startswith("127.") or ipv6 == "::1"
        preferred = bool(stat.isup and not is_loopback and (ipv4 or mac))
        interfaces.append(
            {
                "name": name,
                "capture_name": capture_name,
                "is_up": bool(stat.isup),
                "speed": int(getattr(stat, "speed", 0) or 0),
                "mtu": int(getattr(stat, "mtu", 0) or 0),
                "ipv4": ipv4,
                "ipv6": ipv6,
                "mac": mac,
                "description": "",
                "guid": "",
                "is_loopback": is_loopback,
                "preferred": preferred,
            }
        )
    try:
        from scapy.arch.windows import get_windows_if_list
    except Exception:
        get_windows = None
    else:
        get_windows = {str(item.get("name", "")): item for item in get_windows_if_list()}

    if get_windows:
        for interface in interfaces:
            info = get_windows.get(interface["name"])
            if not info:
                continue
            interface["description"] = str(info.get("description", "") or "")
            interface["guid"] = str(info.get("guid", "") or "")
    interfaces.sort(key=_interface_sort_key)
    return interfaces


def detect_live_interface(preferred: str | None = None) -> str:
    available = list_live_interfaces()
    ethernet_keywords = ("ethernet",)
    excluded_keywords = ("wi-fi", "wifi", "wireless", "wlan")

    def _is_ethernet_candidate(interface: dict[str, Any]) -> bool:
        haystack = " ".join(
            str(interface.get(key, "") or "").lower()
            for key in ("name", "description", "guid", "capture_name")
        )
        return any(keyword in haystack for keyword in ethernet_keywords) and not any(keyword in haystack for keyword in excluded_keywords)

    for interface in available:
        if _is_ethernet_candidate(interface):
            return str(interface["name"])

    if preferred:
        preferred_lower = preferred.lower()
        for interface in available:
            if interface["name"] == preferred:
                return str(interface["name"])
            if interface.get("capture_name") == preferred:
                return str(interface["name"])
            if str(interface.get("description", "")).lower() == preferred_lower:
                return str(interface["name"])
            if str(interface.get("guid", "")).lower() == preferred_lower:
                return str(interface["name"])
    for interface in available:
        if interface.get("preferred"):
            return str(interface["name"])
    try:
        from scapy.all import conf

        if getattr(conf, "iface", None):
            return str(conf.iface)
    except Exception:
        pass
    return available[0]["name"] if available else (preferred or "")


class ReplayWorker:
    MAX_GAP_SECONDS = 3.0

    def __init__(
        self,
        channel: str,
        engine: ChannelEngine,
        source_path: Path,
        speed: float,
        fault: FaultConfig,
        on_finish: Callable[[bool], None] | None = None,
    ) -> None:
        self.channel = channel
        self.engine = engine
        self.source_path = Path(source_path)
        self.speed = max(0.1, float(speed))
        self.fault = fault
        self.on_finish = on_finish
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.base_ts = 0.0
        self.start_monotonic = 0.0

    def load(self) -> None:
        if not self.source_path.exists():
            raise FileNotFoundError(self.source_path)
        self.base_ts = 0.0

    def _wait_for_gap(self, gap_seconds: float) -> bool:
        gap_seconds = min(max(0.0, gap_seconds), self.MAX_GAP_SECONDS)
        deadline = time.monotonic() + gap_seconds
        paused_at: float | None = None
        while True:
            if self.stop_event.is_set():
                return False
            if not self.pause_event.is_set():
                if paused_at is None:
                    paused_at = time.monotonic()
                time.sleep(0.05)
                continue
            if paused_at is not None:
                deadline += time.monotonic() - paused_at
                paused_at = None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return True
            time.sleep(min(0.05, remaining))

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        if not self.source_path.exists():
            self.load()

        def run() -> None:
            try:
                reader = iterate_pcap(self.source_path, self.channel)
                self.start_monotonic = time.monotonic()
                self.base_ts = 0.0
                previous_original_ts: float | None = None
                for event in reader:
                    if self.stop_event.is_set():
                        break
                    if self.base_ts == 0.0:
                        self.base_ts = event.timestamp
                    gap = 0.0 if previous_original_ts is None else (event.timestamp - previous_original_ts) / self.speed
                    if not self._wait_for_gap(gap):
                        break
                    original_elapsed = event.timestamp - self.base_ts
                    previous_original_ts = event.timestamp
                    live_event = replace(event, timestamp=time.time())
                    stop_requested = False
                    for emitted in self._apply_faults(live_event, original_elapsed):
                        wait_for = emitted.timestamp - time.time()
                        if wait_for > 0 and not self._wait_for_gap(wait_for):
                            stop_requested = True
                            break
                        self.engine.record_packet(emitted)
                    if stop_requested:
                        break
            except Exception:
                LOGGER.exception("Replay worker failed for %s", self.channel)
            finally:
                self.engine.config.running = False
                self.thread = None
                if self.on_finish is not None:
                    try:
                        self.on_finish(not self.stop_event.is_set())
                    except Exception:
                        LOGGER.exception("Replay completion callback failed for %s", self.channel)

        self.stop_event.clear()
        self.pause_event.set()
        self.thread = threading.Thread(target=run, name=f"replay-{self.channel}", daemon=True)
        self.thread.start()

    def _apply_faults(self, event: PacketEvent, elapsed: float) -> list[PacketEvent]:
        if not self.fault.enabled or self.fault.fault_type == FaultType.none:
            return [event]
        if elapsed < self.fault.start_elapsed:
            return [event]
        if self.fault.fault_type == FaultType.heartbeat_loss:
            if event.is_heartbeat and (not self.fault.source_mac or event.src_mac.lower() == self.fault.source_mac.lower()):
                return []
            return [event]
        if self.fault.fault_type == FaultType.arp_ghost_spike:
            if event.is_arp and event.arp_opcode == 1 and (not self.fault.target_ip or event.arp_target_ip == self.fault.target_ip):
                extra = max(1, int(round(self.fault.factor)))
                return [event] + [PacketEvent(**{**asdict(event), "timestamp": event.timestamp + (i + 1) * 0.01}) for i in range(extra - 1)]
            return [event]
        if self.fault.fault_type == FaultType.jitter_ramp:
            if event.is_udp and self.fault.flow_id:
                if f"{event.src_ip}:{event.src_port}->{event.dst_ip}:{event.dst_port}" == self.fault.flow_id:
                    ramp = min(20.0, max(1.0, 1.0 + ((elapsed - self.fault.start_elapsed) / 120.0)))
                    extra_delay = min(3.0, max(0.05, (ramp - 1.0) * 0.25))
                    return [PacketEvent(**{**asdict(event), "timestamp": event.timestamp + extra_delay})]
            return [event]
        return [event]

    def pause(self) -> None:
        self.pause_event.clear()

    def resume(self) -> None:
        self.pause_event.set()

    def restart(self) -> None:
        self.stop()
        self.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.pause_event.set()
        self.thread = None


class LiveWorker:
    def __init__(self, channel: str, engine: ChannelEngine, interface_name: str) -> None:
        self.channel = channel
        self.engine = engine
        self.interface_name = interface_name
        self.capture_interface_name = ""
        self.sniffer: Optional[Any] = None
        self.packet_queue: queue.Queue[Any] = queue.Queue(maxsize=8192)
        self.processor: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.dropped_packets = 0
        self.enqueued_packets = 0
        self.processed_packets = 0
        self._log = logging.getLogger(f"backend.runtime.{channel}.live")

    def start(self) -> None:
        try:
            from scapy.all import AsyncSniffer
        except Exception as exc:
            raise RuntimeError("Live capture requires scapy in the active Python environment.") from exc
        if self.sniffer is not None:
            return
        selected_interface = detect_live_interface(self.interface_name or None)
        if not selected_interface:
            raise RuntimeError("No capture interface was found. Select an interface or install/enable a network adapter.")
        self.interface_name = selected_interface
        self.capture_interface_name = _resolve_capture_interface_name(selected_interface)
        if not self.capture_interface_name:
            raise RuntimeError(f"Unable to resolve a capture device for {selected_interface}.")
        self.packet_queue = queue.Queue(maxsize=8192)
        self.stop_event.clear()
        self.dropped_packets = 0
        self.enqueued_packets = 0
        self.processed_packets = 0
        self._log.debug(
            "[%s] live capture starting on %s (%s) with queue maxsize=%s",
            self.channel,
            self.interface_name,
            self.capture_interface_name,
            self.packet_queue.maxsize,
        )

        def handler(pkt) -> None:
            event = normalize_packet(pkt, self.channel, source="live")
            if event is None:
                return
            try:
                self.packet_queue.put_nowait(event)
                self.enqueued_packets += 1
                if self.enqueued_packets % 1000 == 0:
                    self._log.debug("[%s] queued live packet=%s queue_size=%s dropped=%s", self.channel, self.enqueued_packets, self.packet_queue.qsize(), self.dropped_packets)
            except queue.Full:
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self.packet_queue.put_nowait(event)
                    self.enqueued_packets += 1
                except queue.Full:
                    self.dropped_packets += 1
                    self._log.warning("[%s] live queue full; dropping packet from sniffer thread=%s dropped=%s queue_size=%s", self.channel, threading.current_thread().name, self.dropped_packets, self.packet_queue.qsize())

        def processor() -> None:
            self._log.debug("[%s] live queue processor started on thread=%s", self.channel, threading.current_thread().name)
            while not self.stop_event.is_set() or not self.packet_queue.empty():
                try:
                    event = self.packet_queue.get(timeout=0.2)
                except queue.Empty:
                    continue
                try:
                    started = time.perf_counter()
                    self.engine.record_packet(event)
                    elapsed = time.perf_counter() - started
                    self.processed_packets += 1
                    if elapsed >= 0.05:
                        self._log.warning("[%s] engine.record_packet took %.3fs on thread=%s processed=%s queue_size=%s", self.channel, elapsed, threading.current_thread().name, self.processed_packets, self.packet_queue.qsize())
                finally:
                    self.packet_queue.task_done()

        self.processor = threading.Thread(target=processor, name=f"live-{self.channel}-processor", daemon=True)
        self.processor.start()
        self.sniffer = AsyncSniffer(iface=self.capture_interface_name, prn=handler, store=False)
        self.sniffer.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        if self.processor is not None:
            self.processor.join(timeout=2.0)
            self._log.debug("[%s] live queue processor stopped on thread=%s", self.channel, threading.current_thread().name)
            self.processor = None


class ChannelRuntime:
    def __init__(self, channel: str, store: SQLiteStore) -> None:
        self.channel = channel
        self.engine = ChannelEngine(channel, store)
        self.store = store
        self.replay: Optional[ReplayWorker] = None
        self.live: Optional[LiveWorker] = None
        self.config = ChannelConfig(channel=channel)
        self.latest_snapshot = self.engine.tick()
        self.replay_finished = False
        self._tick_stop = threading.Event()
        self._ticker: Optional[threading.Thread] = None
        self._tick_log = logging.getLogger(f"backend.runtime.{channel}.ticker")
        self._start_ticker()

    def _on_replay_finished(self, completed: bool) -> None:
        with self.engine._locked("replay_finished"):
            self.replay_finished = bool(completed)
        if completed:
            self.latest_snapshot = self.engine.tick()

    def _snapshot_payload(self, snapshot: dict) -> dict:
        if self.engine.config.source_mode == SourceMode.replay:
            if self.replay_finished:
                session_state = "finished"
            elif self.engine.config.paused:
                session_state = "paused"
            elif self.engine.config.running:
                session_state = "running"
            else:
                session_state = "idle"
        elif self.engine.config.source_mode == SourceMode.live:
            session_state = "running" if self.engine.config.running else "idle"
        else:
            session_state = "idle"
        return {
            **snapshot,
            "session_state": session_state,
            "source_running": bool(self.engine.config.running),
            "source_paused": bool(self.engine.config.paused),
        }

    def _start_ticker(self) -> None:
        if self._ticker and self._ticker.is_alive():
            return

        def run() -> None:
            self._tick_log.debug("[%s] ticker started on thread=%s", self.channel, threading.current_thread().name)
            while not self._tick_stop.is_set():
                started = time.perf_counter()
                try:
                    self.tick()
                except Exception:
                    LOGGER.exception("Ticker tick failed for %s", self.channel)
                elapsed = time.perf_counter() - started
                if elapsed >= 0.05:
                    self._tick_log.warning("[%s] tick took %.3fs on thread=%s", self.channel, elapsed, threading.current_thread().name)
                sleep_for = max(0.0, 1.0 - elapsed)
                if self._tick_stop.wait(timeout=sleep_for):
                    break
            self._tick_log.debug("[%s] ticker stopped on thread=%s", self.channel, threading.current_thread().name)

        self._ticker = threading.Thread(target=run, name=f"{self.channel.lower()}-ticker", daemon=True)
        self._ticker.start()

    def _stop_ticker(self) -> None:
        self._tick_stop.set()
        ticker = self._ticker
        self._ticker = None
        if ticker and ticker.is_alive():
            ticker.join(timeout=2.0)

    def configure_upload(self, file_path: Path, uploaded_name: str, speed: float = 1.0, fault: Optional[FaultConfig] = None) -> None:
        self.stop()
        self.replay_finished = False
        fault = fault or FaultConfig()
        config = ChannelConfig(
            channel=self.channel,
            source_mode=SourceMode.replay,
            source_path=str(file_path),
            speed_multiplier=speed,
            fault=fault,
            uploaded_name=uploaded_name,
            running=True,
            banner=f"Starting replay for {uploaded_name}...",
        )
        self.engine.configure(config)
        self.replay = ReplayWorker(self.channel, self.engine, file_path, speed, fault, on_finish=self._on_replay_finished)
        starter = self.replay

        def launch_replay() -> None:
            try:
                starter.start()
                if self.replay is starter:
                    self.engine.configure(
                        ChannelConfig(
                            channel=self.channel,
                            source_mode=SourceMode.replay,
                            source_path=str(file_path),
                            speed_multiplier=speed,
                            fault=fault,
                            running=True,
                            uploaded_name=uploaded_name,
                            banner=f"Replay running from {uploaded_name}.",
                        )
                    )
            except Exception as exc:
                LOGGER.exception("Failed to start replay for %s", self.channel)
                if self.replay is starter:
                    self.engine.configure(
                        ChannelConfig(
                            channel=self.channel,
                            source_mode=SourceMode.idle,
                            fault=FaultConfig(),
                            running=False,
                            banner=f"Replay failed to start: {exc}",
                        )
                    )

        threading.Thread(target=launch_replay, name=f"{self.channel.lower()}-replay-starter", daemon=True).start()

    def configure_live(self, interface_name: str, fault: Optional[FaultConfig] = None) -> None:
        self.stop()
        self.replay_finished = False
        fault = fault or FaultConfig()
        selected_interface = detect_live_interface(interface_name or None)
        config = ChannelConfig(channel=self.channel, source_mode=SourceMode.live, interface_name=selected_interface, fault=fault, running=True)
        self.engine.configure(config)
        self.live = LiveWorker(self.channel, self.engine, selected_interface)
        self.live.start()

    def set_fault(self, fault: FaultConfig) -> None:
        self.config = replace(self.config, fault=fault)
        self.engine.configure(
            replace(
                self.engine.config,
                fault=fault,
                banner="Fault settings saved. Use Start Upload Replay or Run Ethernet to apply them.",
            )
        )

    def stop(self) -> None:
        if self.replay:
            self.replay.stop()
            self.replay = None
        if self.live:
            self.live.stop()
            self.live = None
        self.replay_finished = False
        self.engine.configure(ChannelConfig(channel=self.channel))

    def shutdown(self) -> None:
        self._stop_ticker()
        self.stop()
        self.engine.shutdown()

    def clear(self, *, clear_store: bool = True) -> None:
        source_path = Path(self.engine.config.source_path) if self.engine.config.source_path else None
        source_mode = self.engine.config.source_mode
        old_engine = self.engine
        self.stop()
        if clear_store:
            self.store.clear_channel(self.channel)
        if source_mode == SourceMode.replay and source_path and source_path.exists():
            try:
                if source_path.parent == UPLOAD_DIR.resolve() or UPLOAD_DIR.resolve() in source_path.resolve().parents:
                    source_path.unlink(missing_ok=True)
            except Exception:
                pass
        old_engine.shutdown()
        self.engine = ChannelEngine(self.channel, self.store)
        self.config = ChannelConfig(channel=self.channel)
        self.replay_finished = False
        self.latest_snapshot = self.engine.tick()

    def pause(self) -> None:
        if self.replay:
            self.replay.pause()
            self.engine.config.paused = True

    def resume(self) -> None:
        if self.replay:
            self.replay.resume()
            self.engine.config.paused = False

    def restart(self) -> None:
        if self.replay:
            self.replay.restart()

    def tick(self) -> dict:
        if self.replay_finished and self.engine.config.source_mode == SourceMode.replay:
            return self._snapshot_payload(self.latest_snapshot.to_dict())
        self.latest_snapshot = self.engine.tick()
        return self._snapshot_payload(self.latest_snapshot.to_dict())

    def snapshot(self) -> dict:
        if self.replay_finished and self.engine.config.source_mode == SourceMode.replay:
            return self._snapshot_payload(self.latest_snapshot.to_dict())
        return self._snapshot_payload(self.engine.last_snapshot.to_dict())


class DashboardRuntime:
    def __init__(self) -> None:
        self.store = SQLiteStore()
        self.channels = {channel: ChannelRuntime(channel, self.store) for channel in CHANNELS}

    def channel(self, channel: str) -> ChannelRuntime:
        return self.channels[channel]

    def snapshot(self, channel: Optional[str] = None) -> dict:
        if channel:
            return self.channels[channel].snapshot()
        return {
            "PN": self.channels[PN].snapshot(),
            "CN": self.channels[CN].snapshot(),
        }

    def combined_overview(self) -> dict:
        pn = self.channels[PN].snapshot()
        cn = self.channels[CN].snapshot()
        rank = {"normal": 0, "advisory": 1, "degraded": 2, "critical": 3}
        return {
            "channels": {
                PN: pn,
                CN: cn,
            },
            "overall_severity": max(pn["overall_severity"], cn["overall_severity"], key=lambda s: rank[s]),
            "active_alerts": len(pn["alerts"]) + len(cn["alerts"]),
        }

    def upload_capture(self, channel: str, file_path: Path, uploaded_name: str, speed: float = 1.0, fault: Optional[FaultConfig] = None) -> dict:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        self.channels[channel].configure_upload(file_path, uploaded_name, speed, fault)
        return self.channels[channel].snapshot()

    def start_live(self, channel: str, interface_name: str, fault: Optional[FaultConfig] = None) -> dict:
        self.channels[channel].configure_live(interface_name, fault)
        return self.channels[channel].snapshot()

    def pause(self, channel: str) -> None:
        self.channels[channel].pause()

    def resume(self, channel: str) -> None:
        self.channels[channel].resume()

    def restart(self, channel: str) -> None:
        self.channels[channel].restart()

    def stop(self, channel: str) -> None:
        self.channels[channel].stop()

    def clear(self, channel: str, *, clear_store: bool = True) -> dict:
        self.channels[channel].clear(clear_store=clear_store)
        return self.channels[channel].snapshot()

    def acknowledge_alert(self, channel: str, metric_id: str) -> bool:
        return self.channels[channel].engine.acknowledge_alert(metric_id)

    def acknowledge_alerts(self, channel: str | None = None) -> int:
        if channel:
            return self.channels[channel].engine.acknowledge_all_alerts()
        total = 0
        for channel_id in CHANNELS:
            total += self.channels[channel_id].engine.acknowledge_all_alerts()
        return total

    def set_alert_mute(self, channel: str, metric_id: str, muted: bool) -> None:
        self.channels[channel].engine.set_alert_mute(metric_id, muted)

    def shutdown(self) -> None:
        for channel in CHANNELS:
            try:
                self.channels[channel].shutdown()
            except Exception:
                LOGGER.exception("Failed to shutdown channel %s", channel)
