"""Tests for the Basic Network Sniffer.

The first test class preserves the behaviour the project's original
test file described (it shipped inside the module, where its tests
could not pass because the callback was incomplete). They pass now.
"""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scapy.all as scapy

from network_sniffer import (analyse_pcap, format_packet, load_pcap,
                             packet_callback, parse_filter, save_pcap)


def run_callback(packet) -> str:
    out = io.StringIO()
    with redirect_stdout(out):
        packet_callback(packet)
    return out.getvalue()


class TestPacketCallback(unittest.TestCase):
    """The original spec, as a real test suite."""

    def test_packet_with_ip_layer(self):
        packet = scapy.IP(src="192.168.1.1", dst="8.8.8.8")
        output = run_callback(packet)
        self.assertIn("Timestamp:", output)
        self.assertIn("Source IP: 192.168.1.1, Destination IP: 8.8.8.8", output)

    def test_packet_with_tcp_layer(self):
        packet = scapy.IP(src="192.168.1.1", dst="8.8.8.8") / scapy.TCP(sport=1234, dport=5678)
        self.assertIn("Source Port: 1234, Destination Port: 5678", run_callback(packet))

    def test_packet_with_udp_layer(self):
        packet = scapy.IP(src="192.168.1.1", dst="8.8.8.8") / scapy.UDP(sport=1234, dport=5678)
        self.assertIn("Source Port: 1234, Destination Port: 5678", run_callback(packet))

    def test_packet_with_dns_layer_query(self):
        packet = (scapy.IP(src="192.168.1.1", dst="8.8.8.8") / scapy.UDP(sport=1234, dport=5678)
                  / scapy.DNS(qd=scapy.DNSRR(rrname="example.com")))
        self.assertIn("DNS Query: example.com", run_callback(packet))

    def test_packet_with_dns_layer_response(self):
        packet = (scapy.IP(src="192.168.1.1", dst="8.8.8.8") / scapy.UDP(sport=1234, dport=5678)
                  / scapy.DNS(qr=1, an=scapy.DNSRR(rrname="example.com", rdata="1.2.3.4")))
        self.assertIn("DNS Response: example.com -> 1.2.3.4", run_callback(packet))

    def test_packet_without_ip_layer(self):
        packet = scapy.TCP(sport=1234, dport=5678)
        self.assertEqual(run_callback(packet), "")

    def test_packet_with_unknown_protocol(self):
        packet = scapy.IP(src="192.168.1.1", dst="8.8.8.8", proto=255)
        output = run_callback(packet)
        self.assertIn("Timestamp:", output)
        self.assertIn("Source IP: 192.168.1.1, Destination IP: 8.8.8.8", output)
        self.assertIn("Protocol: Unknown (255)", output)


class TestFilters(unittest.TestCase):
    def setUp(self):
        self.tcp_web = scapy.IP(src="10.0.0.5", dst="93.184.216.34") / scapy.TCP(sport=51000, dport=443)
        self.dns_pkt = (scapy.IP(src="10.0.0.5", dst="8.8.8.8") / scapy.UDP(sport=53000, dport=53)
                        / scapy.DNS(qd=scapy.DNSQR(qname="example.com")))

    def test_protocol_filter(self):
        self.assertTrue(parse_filter("tcp").matches(self.tcp_web))
        self.assertFalse(parse_filter("udp").matches(self.tcp_web))
        self.assertTrue(parse_filter("dns").matches(self.dns_pkt))

    def test_port_and_host_filters(self):
        self.assertTrue(parse_filter("port 443").matches(self.tcp_web))
        self.assertTrue(parse_filter("dst port 443").matches(self.tcp_web))
        self.assertFalse(parse_filter("dst port 80").matches(self.tcp_web))
        self.assertTrue(parse_filter("host 8.8.8.8").matches(self.dns_pkt))
        self.assertFalse(parse_filter("host 1.1.1.1").matches(self.dns_pkt))

    def test_combined_filter(self):
        f = parse_filter("udp port 53")
        self.assertTrue(f.matches(self.dns_pkt))
        self.assertFalse(f.matches(self.tcp_web))

    def test_bad_filter_token_raises(self):
        with self.assertRaises(ValueError):
            parse_filter("carrier pigeon")


class TestPcap(unittest.TestCase):
    def test_roundtrip_and_analyse(self):
        packets = [
            scapy.Ether() / scapy.IP(src="192.168.1.1", dst="8.8.8.8") / scapy.TCP(sport=1234, dport=80),
            scapy.Ether() / scapy.IP(src="192.168.1.1", dst="1.1.1.1") / scapy.UDP(sport=1234, dport=53),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "test.pcap")
            save_pcap(path, packets)
            self.assertEqual(len(load_pcap(path)), 2)
            out = io.StringIO()
            with redirect_stdout(out):
                summary = analyse_pcap(path, parse_filter("tcp"))
            self.assertEqual(summary, {"total": 2, "shown": 1})
            self.assertIn("Destination Port: 80", out.getvalue())


if __name__ == "__main__":
    unittest.main()
