from __future__ import annotations

import ipaddress
import logging
import time
from pathlib import Path
from typing import Iterator, Optional

from .models import PacketEvent

LOGGER = logging.getLogger("backend.parser")

try:
    from scapy.contrib.cdp import CDPv2_HDR
    from scapy.contrib.lldp import LLDPDU
    from scapy.layers.inet import IP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether, STP

    _SCAPY_PROTOCOLS_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    LOGGER.error("Scapy protocol import failed: %s", exc)
    _SCAPY_PROTOCOLS_AVAILABLE = False


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _is_multicast_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_multicast
    except Exception:
        return False


def _is_broadcast_mac(mac: str) -> bool:
    return mac.lower() == "ff:ff:ff:ff:ff:ff"


def normalize_packet(packet, channel: str, source: str = "live", timestamp: Optional[float] = None) -> Optional[PacketEvent]:
    if not _SCAPY_PROTOCOLS_AVAILABLE:
        return None

    try:
        ts = float(timestamp if timestamp is not None else getattr(packet, "time", time.time()))
        length = _safe_int(len(packet))
        src_mac = ""
        dst_mac = ""
        src_ip = ""
        dst_ip = ""
        src_port = None
        dst_port = None
        protocol = "OTHER"
        layers = []
        is_udp = False
        is_arp = False
        is_broadcast = False
        is_multicast = False
        arp_opcode = 0
        arp_sender_ip = ""
        arp_target_ip = ""
        arp_sender_mac = ""
        is_heartbeat = False
        heartbeat_protocol = ""
        stp_root_mac = ""
        stp_path_cost = 0
        stp_topology_change = False
        stp_bridge_mac = ""
        is_gratuitous_arp = False

        if packet.haslayer(Ether):
            ether = packet[Ether]
            src_mac = getattr(ether, "src", "") or ""
            dst_mac = getattr(ether, "dst", "") or ""
            is_broadcast = _is_broadcast_mac(dst_mac)
            is_multicast = dst_mac.lower().startswith(("01:00:5e", "33:33"))
            layers.append("eth")

        if packet.haslayer(ARP):
            arp = packet[ARP]
            is_arp = True
            protocol = "ARP"
            layers.append("arp")
            arp_opcode = _safe_int(getattr(arp, "op", 0))
            arp_sender_ip = getattr(arp, "psrc", "") or ""
            arp_target_ip = getattr(arp, "pdst", "") or ""
            arp_sender_mac = getattr(arp, "hwsrc", "") or src_mac
            src_ip = arp_sender_ip
            dst_ip = arp_target_ip
            is_broadcast = is_broadcast or _is_broadcast_mac(dst_mac)
            is_gratuitous_arp = arp_opcode == 2 and arp_sender_ip == arp_target_ip
            return PacketEvent(
                timestamp=ts,
                channel=channel,
                length=length,
                src_mac=arp_sender_mac,
                dst_mac=dst_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                layers=tuple(layers),
                source=source,
                arp_opcode=arp_opcode,
                arp_sender_ip=arp_sender_ip,
                arp_target_ip=arp_target_ip,
                arp_sender_mac=arp_sender_mac,
                is_udp=False,
                is_arp=True,
                is_broadcast=is_broadcast,
                is_multicast=is_multicast,
                is_gratuitous_arp=is_gratuitous_arp,
            )

        if packet.haslayer(IP):
            ip = packet[IP]
            src_ip = getattr(ip, "src", "") or ""
            dst_ip = getattr(ip, "dst", "") or ""
            is_multicast = is_multicast or _is_multicast_ip(dst_ip)
            is_broadcast = is_broadcast or dst_ip == "255.255.255.255"
            layers.append("ip")
            if packet.haslayer(UDP):
                udp = packet[UDP]
                src_port = _safe_int(getattr(udp, "sport", 0))
                dst_port = _safe_int(getattr(udp, "dport", 0))
                protocol = "UDP"
                is_udp = True
                layers.append("udp")
            else:
                protocol = "IP"

        elif packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            src_ip = getattr(ipv6, "src", "") or ""
            dst_ip = getattr(ipv6, "dst", "") or ""
            is_multicast = is_multicast or dst_ip.lower().startswith("ff")
            layers.append("ipv6")
            if packet.haslayer(UDP):
                udp = packet[UDP]
                src_port = _safe_int(getattr(udp, "srcport", 0))
                dst_port = _safe_int(getattr(udp, "dstport", 0))
                protocol = "UDP"
                is_udp = True
                layers.append("udp")
            else:
                protocol = "IPv6"

        if packet.haslayer(STP):
            stp = packet[STP]
            protocol = "STP"
            layers.append("stp")
            stp_root_mac = getattr(stp, "rootmac", "") or ""
            stp_bridge_mac = getattr(stp, "bridgemac", "") or ""
            stp_path_cost = _safe_int(getattr(stp, "pathcost", 0))
            flags = _safe_int(getattr(stp, "bpduflags", 0))
            stp_topology_change = bool(flags & 0x01)
            is_heartbeat = True
            heartbeat_protocol = "STP"

        if packet.haslayer(LLDPDU):
            protocol = "LLDP"
            layers.append("lldp")
            is_heartbeat = True
            heartbeat_protocol = "LLDP"

        if packet.haslayer(CDPv2_HDR):
            protocol = "CDP"
            layers.append("cdp")
            is_heartbeat = True
            heartbeat_protocol = "CDP"

        return PacketEvent(
            timestamp=ts,
            channel=channel,
            length=length,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            layers=tuple(dict.fromkeys(layers)),
            source=source,
            arp_opcode=arp_opcode,
            arp_sender_ip=arp_sender_ip,
            arp_target_ip=arp_target_ip,
            arp_sender_mac=arp_sender_mac,
            is_udp=is_udp,
            is_arp=is_arp,
            is_broadcast=is_broadcast,
            is_multicast=is_multicast,
            is_heartbeat=is_heartbeat,
            heartbeat_protocol=heartbeat_protocol,
            stp_root_mac=stp_root_mac,
            stp_path_cost=stp_path_cost,
            stp_topology_change=stp_topology_change,
            stp_bridge_mac=stp_bridge_mac,
            is_gratuitous_arp=is_gratuitous_arp,
        )
    except Exception as exc:  # pragma: no cover
        LOGGER.debug("Unable to normalize packet: %s", exc, exc_info=True)
        return None


def iterate_pcap(path: Path, channel: str) -> Iterator[PacketEvent]:
    try:
        from scapy.utils import PcapNgReader, PcapReader
    except Exception as exc:  # pragma: no cover
        LOGGER.error("Scapy reader unavailable: %s", exc)
        return

    suffix = path.suffix.lower()
    candidates = [PcapNgReader, PcapReader] if suffix == ".pcapng" else [PcapReader, PcapNgReader]
    reader = None
    for candidate in candidates:
        try:
            reader = candidate(str(path))
            break
        except Exception:
            reader = None
    if reader is None:
        raise RuntimeError(f"Unable to open capture file: {path}")

    try:
        for packet in reader:
            event = normalize_packet(packet, channel=channel, source="upload")
            if event is not None:
                yield event
    finally:
        try:
            reader.close()
        except Exception:
            pass
