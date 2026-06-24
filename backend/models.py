from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from math import sqrt
from typing import Deque, Optional


class Severity(str, Enum):
    normal = "normal"
    advisory = "advisory"
    degraded = "degraded"
    critical = "critical"


class ChannelId(str, Enum):
    PN = "PN"
    CN = "CN"


class SourceMode(str, Enum):
    idle = "idle"
    upload = "upload"
    replay = "replay"
    live = "live"


class FaultType(str, Enum):
    none = "none"
    heartbeat_loss = "heartbeat_loss"
    jitter_ramp = "jitter_ramp"
    arp_ghost_spike = "arp_ghost_spike"


@dataclass(slots=True)
class FaultConfig:
    enabled: bool = False
    fault_type: FaultType = FaultType.none
    source_mac: str = ""
    target_ip: str = ""
    flow_id: str = ""
    start_elapsed: float = 1.0
    factor: float = 3.0


@dataclass(slots=True)
class AdaptiveBaseline:
    mean: float = 0.0
    variance: float = 0.0
    samples: int = 0
    last_updated: float = 0.0

    @property
    def stddev(self) -> float:
        return sqrt(self.variance) if self.variance > 0 else 0.0

    @property
    def reliable(self) -> bool:
        return self.samples >= 8

    def observe(self, value: float, *, weight: float = 0.18, now: float = 0.0) -> None:
        value = float(value)
        if self.samples <= 0:
            self.mean = value
            self.variance = 0.0
            self.samples = 1
            self.last_updated = now
            return

        alpha = min(0.35, max(0.05, weight))
        previous_mean = self.mean
        delta = value - previous_mean
        self.mean = previous_mean + alpha * delta
        self.variance = max(0.0, (1.0 - alpha) * (self.variance + alpha * delta * delta))
        self.samples += 1
        self.last_updated = now


@dataclass(slots=True)
class PacketEvent:
    timestamp: float
    channel: str
    length: int
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "OTHER"
    layers: tuple[str, ...] = ()
    source: str = "live"
    arp_opcode: int = 0
    arp_sender_ip: str = ""
    arp_target_ip: str = ""
    arp_sender_mac: str = ""
    is_udp: bool = False
    is_arp: bool = False
    is_broadcast: bool = False
    is_multicast: bool = False
    is_heartbeat: bool = False
    heartbeat_protocol: str = ""
    stp_root_mac: str = ""
    stp_path_cost: int = 0
    stp_topology_change: bool = False
    stp_bridge_mac: str = ""
    is_gratuitous_arp: bool = False


@dataclass(slots=True)
class MetricSnapshot:
    metric_id: str
    label: str
    severity: Severity
    value: float | int | str
    baseline: float | int | str | None
    baseline_samples: int = 0
    learning_state: str = "learning"
    interpretation: str = ""
    recommendation: str = ""
    correlation_note: str = ""
    confidence: int = 0
    occurrence_count: int = 0
    trend: str = "flat"
    current_duration: float = 0.0
    acknowledged: bool = False
    resolved: bool = False
    muted: bool = False


@dataclass(slots=True)
class AlertEvent:
    ts: float
    channel: str
    metric_id: str
    metric_label: str
    severity: Severity
    interpretation: str
    recommendation: str
    current_value: float | int | str
    baseline_value: float | int | str | None
    confidence: int
    correlation_note: str = ""
    occurrence_count: int = 0
    active: bool = True
    acknowledged: bool = False
    resolved: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    duration_seconds: float = 0.0


@dataclass(slots=True)
class FlowState:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=512))
    intervals: Deque[float] = field(default_factory=lambda: deque(maxlen=512))
    expected_interval: float = 0.0
    baseline_jitter: float = 0.0
    baseline_loss: float = 0.0
    monitored: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    silent_since: float = 0.0


@dataclass(slots=True)
class HeartbeatState:
    device_mac: str
    protocol: str
    intervals: Deque[float] = field(default_factory=lambda: deque(maxlen=128))
    last_seen: float = 0.0
    baseline_interval: float = 0.0
    observed_since: float = 0.0


@dataclass(slots=True)
class DeviceState:
    device_id: str
    src_mac: str = ""
    src_ip: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    source_ports: set[int] = field(default_factory=set)
    destination_groups: set[str] = field(default_factory=set)
    intervals: Deque[float] = field(default_factory=lambda: deque(maxlen=256))
    expected_interval: float = 0.0
    avg_jitter_ms: float = 0.0
    max_jitter_ms: float = 0.0
    silent: bool = False
    silence_started: float = 0.0
    silence_event_ended: float = 0.0
    silence_duration: float = 0.0


@dataclass(slots=True)
class ChannelConfig:
    channel: str
    source_mode: SourceMode = SourceMode.idle
    source_path: str = ""
    interface_name: str = ""
    speed_multiplier: float = 1.0
    fault: FaultConfig = field(default_factory=FaultConfig)
    running: bool = False
    paused: bool = False
    uploaded_name: str = ""
    banner: str = ""


@dataclass(slots=True)
class ChannelSnapshot:
    channel: str
    ts: float
    total_packets: int = 0
    total_bytes: int = 0
    pps: int = 0
    bps: int = 0
    broadcast_packets: int = 0
    multicast_packets: int = 0
    udp_packets: int = 0
    arp_packets: int = 0
    active_devices: int = 0
    active_flows: int = 0
    alert_counts: dict[str, int] = field(default_factory=dict)
    overall_severity: Severity = Severity.normal
    alert_mutes: dict[str, bool] = field(default_factory=dict)
    metrics: list[MetricSnapshot] = field(default_factory=list)
    alerts: list[AlertEvent] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)
    jitter_series: list[dict] = field(default_factory=list)
    loss_series: list[dict] = field(default_factory=list)
    burst_series: list[dict] = field(default_factory=list)
    ratio_series: list[dict] = field(default_factory=list)
    heartbeat_series: list[dict] = field(default_factory=list)
    heartbeat_history: list[dict] = field(default_factory=list)
    stp_series: list[dict] = field(default_factory=list)
    stp_root_series: list[dict] = field(default_factory=list)
    arp_series: list[dict] = field(default_factory=list)
    silence_series: list[dict] = field(default_factory=list)
    event_timeline: list[dict] = field(default_factory=list)
    devices: list[dict] = field(default_factory=list)
    flows: list[dict] = field(default_factory=list)
    fault_banner: str = ""
    source_mode: str = "idle"
    source_name: str = ""

    def to_dict(self) -> dict:
        def serialize(value):
            if hasattr(value, "value"):
                return value.value
            if isinstance(value, tuple):
                return [serialize(item) for item in value]
            if isinstance(value, list):
                return [serialize(item) for item in value]
            if isinstance(value, dict):
                return {key: serialize(item) for key, item in value.items()}
            return value

        return {
            "channel": self.channel,
            "ts": self.ts,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "pps": self.pps,
            "bps": self.bps,
            "broadcast_packets": self.broadcast_packets,
            "multicast_packets": self.multicast_packets,
            "udp_packets": self.udp_packets,
            "arp_packets": self.arp_packets,
            "active_devices": self.active_devices,
            "active_flows": self.active_flows,
            "alert_counts": self.alert_counts,
            "overall_severity": self.overall_severity.value,
            "alert_mutes": self.alert_mutes,
            "metrics": [serialize(asdict(metric)) for metric in self.metrics],
            "alerts": [serialize(asdict(alert)) for alert in self.alerts],
            "history": self.history,
            "jitter_series": self.jitter_series,
            "loss_series": self.loss_series,
            "burst_series": self.burst_series,
            "ratio_series": self.ratio_series,
            "heartbeat_series": self.heartbeat_series,
            "heartbeat_history": self.heartbeat_history,
            "stp_series": self.stp_series,
            "stp_root_series": self.stp_root_series,
            "arp_series": self.arp_series,
            "silence_series": self.silence_series,
            "event_timeline": self.event_timeline,
            "devices": self.devices,
            "flows": self.flows,
            "fault_banner": self.fault_banner,
            "source_mode": self.source_mode,
            "source_name": self.source_name,
        }
