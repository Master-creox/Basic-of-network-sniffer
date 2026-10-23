"""Basic Network Sniffer — capture, decode and filter live traffic.

A small, readable packet sniffer built on Scapy. It does what the
README promises:

- live packet capture with a human-readable decode
  (Ethernet / IP / TCP / UDP / ICMP / DNS)
- simple custom filters (protocol, IP address, port)
- save captures to PCAP and analyse PCAP files later
- optional logging of every decoded packet to a file

Design notes
------------
``format_packet()`` turns a packet into text (pure and testable);
``packet_callback()`` prints it. Packets without an IP layer produce
no output — the sniffer is about IP traffic.

Live capture needs administrator/root privileges on most systems and
is the only part that touches the network. Everything else (filters,
formatting, PCAP analysis) works offline on saved traffic.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from scapy.all import DNS, ICMP, IP, TCP, UDP, rdpcap, sniff, wrpcap

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _clean_name(value) -> str:
    """DNS names arrive as bytes with a trailing dot — normalise them."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).rstrip(".")


def _first(field):
    """First DNS record of a section, across Scapy versions.

    Newer Scapy exposes qd/an as list-like PacketListFields; older
    versions return a single record (or None). Normalise to one record.
    """
    if field is None:
        return None
    try:
        return field[0] if len(field) > 0 else None
    except (TypeError, KeyError, IndexError):
        return field


def format_packet(packet) -> str:
    """Return the decoded text for one packet ('' when it has no IP layer)."""
    if IP not in packet:
        return ""
    ip = packet[IP]
    lines = [
        f"Timestamp: {datetime.now()}",
        f"Source IP: {ip.src}, Destination IP: {ip.dst}",
        f"Protocol: {PROTOCOL_NAMES.get(ip.proto, f'Unknown ({ip.proto})')}",
    ]
    layer = None
    if TCP in packet:
        layer = packet[TCP]
    elif UDP in packet:
        layer = packet[UDP]
    if layer is not None:
        lines.append(f"Source Port: {layer.sport}, Destination Port: {layer.dport}")
    if ICMP in packet:
        icmp = packet[ICMP]
        lines.append(f"ICMP Type: {icmp.type}, Code: {icmp.code}")
    if DNS in packet:
        dns = packet[DNS]
        if dns.qr == 0:
            qd = _first(dns.qd)
            if qd is not None:
                name = getattr(qd, "qname", None) or getattr(qd, "rrname", "")
                lines.append(f"DNS Query: {_clean_name(name)}")
        elif dns.qr == 1:
            an = _first(dns.an)
            if an is not None:
                lines.append(f"DNS Response: {_clean_name(an.rrname)} -> {an.rdata}")
    return "\n".join(lines)


def packet_callback(packet) -> None:
    """Scapy callback: print the decoded packet (IP traffic only)."""
    text = format_packet(packet)
    if text:
        print(text)
        logging.getLogger("network_sniffer").info(text.replace("\n", " | "))


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

@dataclass
class PacketFilter:
    """A simple filter: every set field must match (logical AND).

    Build one from a string with :func:`parse_filter`, e.g.
    ``parse_filter("tcp port 443")`` or ``parse_filter("host 8.8.8.8")``.
    """
    protocol: str | None = None      # tcp | udp | icmp | dns
    src_ip: str | None = None
    dst_ip: str | None = None
    host: str | None = None          # either direction
    port: int | None = None          # either direction
    src_port: int | None = None
    dst_port: int | None = None

    def matches(self, packet) -> bool:
        if IP not in packet:
            return False
        ip = packet[IP]
        if self.host and ip.src != self.host and ip.dst != self.host:
            return False
        if self.src_ip and ip.src != self.src_ip:
            return False
        if self.dst_ip and ip.dst != self.dst_ip:
            return False
        if self.protocol:
            proto = self.protocol.lower()
            if proto == "dns" and DNS not in packet:
                return False
            if proto == "tcp" and TCP not in packet:
                return False
            if proto == "udp" and UDP not in packet:
                return False
            if proto == "icmp" and ICMP not in packet:
                return False
        layer = packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
        ports = (layer.sport, layer.dport) if layer is not None else ()
        if self.port is not None and self.port not in ports:
            return False
        if self.src_port is not None and (not ports or ports[0] != self.src_port):
            return False
        if self.dst_port is not None and (not ports or ports[1] != self.dst_port):
            return False
        return True


def parse_filter(expression: str | None) -> PacketFilter:
    """Parse a small filter expression into a :class:`PacketFilter`.

    Supported tokens (space separated, ``and`` is ignored):
    ``tcp`` ``udp`` ``icmp`` ``dns`` ``port N`` ``src port N``
    ``dst port N`` ``host IP`` ``src host IP`` ``dst host IP``
    """
    result = PacketFilter()
    if not expression:
        return result
    tokens = expression.lower().split()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("tcp", "udp", "icmp", "dns"):
            result.protocol = tok
            i += 1
        elif tok == "and":
            i += 1
        elif tok == "port" and i + 1 < len(tokens):
            result.port = int(tokens[i + 1]); i += 2
        elif tok in ("src", "dst") and i + 2 < len(tokens) and tokens[i + 1] == "port":
            setattr(result, f"{tok}_port", int(tokens[i + 2])); i += 3
        elif tok == "host" and i + 1 < len(tokens):
            result.host = tokens[i + 1]; i += 2
        elif tok in ("src", "dst") and i + 2 < len(tokens) and tokens[i + 1] == "host":
            setattr(result, f"{tok}_ip", tokens[i + 2]); i += 3
        else:
            raise ValueError(f"Unsupported filter token: {tok!r}")
    return result


# ---------------------------------------------------------------------------
# PCAP save / load / analysis
# ---------------------------------------------------------------------------

def save_pcap(path: str, packets) -> None:
    """Save captured packets to a PCAP file."""
    wrpcap(path, list(packets))


def load_pcap(path: str):
    """Load packets from a PCAP file."""
    return rdpcap(path)


def analyse_pcap(path: str, packet_filter: PacketFilter | None = None) -> dict:
    """Decode every packet in a PCAP file; print matches, return a summary."""
    packets = load_pcap(path)
    shown = 0
    for packet in packets:
        if packet_filter is not None and not packet_filter.matches(packet):
            continue
        text = format_packet(packet)
        if text:
            print(text)
            print("-" * 60)
            shown += 1
    return {"total": len(packets), "shown": shown}


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------

def setup_logging(log_file: str | None) -> None:
    """Log decoded packets to a file (in addition to the console)."""
    if not log_file:
        return
    logging.basicConfig(filename=log_file, level=logging.INFO,
                        format="%(message)s", force=True)


def sniff_live(iface: str | None = None, count: int = 0,
               packet_filter: PacketFilter | None = None,
               save_to: str | None = None) -> list:
    """Capture live packets (needs admin/root). Returns the packets seen.

    ``count=0`` captures until Ctrl+C. Matching packets are printed as
    they arrive; all captured packets are saved when ``save_to`` is set.
    """
    captured = []

    def _handle(packet):
        captured.append(packet)
        if packet_filter is None or packet_filter.matches(packet):
            packet_callback(packet)
            print("-" * 60)

    try:
        sniff(iface=iface, count=count, prn=_handle, store=False)
    except PermissionError:
        raise PermissionError(
            "Live capture needs administrator/root privileges. "
            "Re-run with sudo (Linux/macOS) or an elevated terminal (Windows)."
        ) from None
    if save_to:
        save_pcap(save_to, captured)
    return captured
