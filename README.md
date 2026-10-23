# Basic Network Packet Sniffer & Analyzer

A Python-based packet-sniffing tool capable of capturing, decoding, and analyzing live network traffic.
Supports protocol-level breakdown, PCAP saving/loading, and customizable filters.

> Looking for the heavy-duty version? See
> [advanced-network-sniffer](https://github.com/Master-creox/advanced-network-sniffer) —
> a zero-dependency engine with its own PCAP parser and threat detectors.
> This project is the readable, Scapy-based starting point.

### ✨ Features
- Live network packet sniffing
- Decode Ethernet, IP, TCP, UDP, ICMP — plus DNS queries & responses
- Custom filters (IP, Port, Protocol)
- Save & Load PCAP files
- Real-time packet logging to a file
- Modular protocol parsers, with a passing test suite

### 🛠 Technologies
Python, Scapy, PCAP

### 📦 Setup
```bash
pip install -r requirements.txt
```

### 📌 Usage
```bash
python sniffer.py                                   # live capture (needs admin/root)
python sniffer.py --filter tcp                      # TCP only
python sniffer.py --filter "host 8.8.8.8"           # one host, both directions
python sniffer.py --filter "udp port 53"            # DNS traffic
python sniffer.py --count 20 --save capture.pcap    # capture 20 packets, save PCAP
python sniffer.py --pcap capture.pcap               # analyse a saved PCAP
python sniffer.py --pcap capture.pcap --log out.log # ... and log the decode
```

Example output:
```
Timestamp: 2026-10-24 04:20:24
Source IP: 192.168.1.10, Destination IP: 8.8.8.8
Protocol: UDP
Source Port: 53000, Destination Port: 53
DNS Query: example.com
```

**Filter syntax:** `tcp` `udp` `icmp` `dns`, `port N`, `src port N`,
`dst port N`, `host IP`, `src host IP`, `dst host IP` — combine freely,
e.g. `--filter "tcp dst port 443"`.

**Note:** live capture requires administrator/root privileges
(`sudo python sniffer.py` on Linux/macOS, elevated terminal on Windows).
PCAP analysis works without any privileges.

### 🧪 Tests
```bash
python -m pytest tests/ -q
```
12 tests: packet decoding (IP/TCP/UDP/ICMP/DNS), the filter engine,
and PCAP save/load round-trips.

### 📁 Layout
- `network_sniffer.py` — decoding, filters, PCAP, live capture
- `sniffer.py` — command-line interface
- `tests/` — test suite

### ⚖️ Ethics
Capture only traffic on networks you own or have permission to monitor.

### License
MIT
