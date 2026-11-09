# CodeAlpha_BasicNetworkSniffer

Task 1 of the CodeAlpha Cyber Security Internship: a basic network sniffer in Python using Scapy.

## Features
- Captures live packets (Ethernet/IP/IPv6/ARP)
- Shows source/destination IPs, protocol, length, TTL
- Shows TCP/UDP ports, TCP flags, ICMP type/code, DNS query names
- Optional payload preview (ASCII + hex)
- BPF filters, packet count limit, interface selection
- Saves captures to `.pcap` (open in Wireshark)
- Protocol statistics summary at the end

## Setup
```bash
pip install scapy
```
- Linux/macOS: run with `sudo`
- Windows: install [Npcap](https://npcap.com) and run the terminal as Administrator

## Usage
```bash
sudo python3 sniffer.py                          # until Ctrl+C
sudo python3 sniffer.py -c 50                    # 50 packets
sudo python3 sniffer.py -f "tcp port 80" --payload
sudo python3 sniffer.py -c 100 -w capture.pcap
```

## How it works
1. `scapy.sniff()` captures frames from the network interface.
2. Each frame is a stack of layers: Ethernet -> IP -> TCP/UDP/ICMP -> payload.
3. The callback inspects each layer, prints key fields, and counts protocols.

## Learning notes
- **TCP flags**: SYN/SYN-ACK/ACK is the three-way handshake; FIN/RST close connections.
- **DNS (UDP/53)**: hostnames are resolved before most connections.
- **HTTP (port 80)** payloads are readable in plaintext; **HTTPS (443)** payloads are encrypted, so only metadata is visible.

## Ethical use
Only capture traffic on networks you own or have written permission to monitor.
