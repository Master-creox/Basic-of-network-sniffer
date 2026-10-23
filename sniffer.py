"""Command-line interface for the Basic Network Sniffer.

Usage:
    python sniffer.py                                  # live capture (needs admin/root)
    python sniffer.py --filter tcp                     # only TCP packets
    python sniffer.py --filter "host 8.8.8.8"          # traffic to/from one host
    python sniffer.py --filter "udp port 53"           # DNS traffic
    python sniffer.py --count 20 --save capture.pcap   # capture 20, save PCAP
    python sniffer.py --pcap capture.pcap              # analyse a saved PCAP
    python sniffer.py --pcap capture.pcap --log out.log
"""
from __future__ import annotations

import argparse
import sys

from network_sniffer import (PacketFilter, analyse_pcap, parse_filter,
                             setup_logging, sniff_live)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="Basic network packet sniffer & analyser (educational).")
    parser.add_argument("--filter", default=None,
                        help='Filter expression, e.g. "tcp", "port 80", '
                             '"host 8.8.8.8", "udp port 53".')
    parser.add_argument("--pcap", default=None,
                        help="Analyse this PCAP file instead of capturing live.")
    parser.add_argument("--iface", default=None,
                        help="Network interface for live capture (default: system default).")
    parser.add_argument("--count", type=int, default=0,
                        help="Stop after N packets in live mode (0 = until Ctrl+C).")
    parser.add_argument("--save", default=None,
                        help="Save live-captured packets to this PCAP file.")
    parser.add_argument("--log", default=None,
                        help="Also write decoded packets to this log file.")
    args = parser.parse_args(argv)

    try:
        packet_filter = parse_filter(args.filter)
    except ValueError as exc:
        print(f"Bad filter: {exc}")
        return 2
    setup_logging(args.log)

    if args.pcap:
        summary = analyse_pcap(args.pcap, packet_filter)
        print(f"PCAP summary: {summary['shown']} packet(s) shown "
              f"out of {summary['total']} total.")
        return 0

    print("Starting live capture — Ctrl+C to stop. "
          "(Live capture needs administrator/root privileges.)")
    try:
        captured = sniff_live(iface=args.iface, count=args.count,
                              packet_filter=packet_filter, save_to=args.save)
    except PermissionError as exc:
        print(exc)
        return 1
    except KeyboardInterrupt:
        print("\nCapture stopped.")
        return 0
    print(f"Captured {len(captured)} packet(s)."
          + (f" Saved to {args.save}." if args.save else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
