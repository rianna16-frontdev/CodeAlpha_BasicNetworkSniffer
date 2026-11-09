#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer

Captures packets with Scapy and prints source/destination IPs, protocol,
ports, TCP flags and a payload preview. Intended for learning and for use
on networks you own or are authorized to monitor.

Usage (needs admin/root privileges):
    sudo python3 sniffer.py                       # capture until Ctrl+C
    sudo python3 sniffer.py -c 50                 # capture 50 packets
    sudo python3 sniffer.py -i eth0 -f "tcp port 80"
    sudo python3 sniffer.py -c 100 -w capture.pcap --payload
"""

import argparse
import datetime
import sys
from collections import Counter

try:
    from scapy.all import (
        sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw,
        ICMPv6EchoRequest, ICMPv6EchoReply,
    )
except ImportError:
    sys.exit("Scapy is not installed. Run: pip install scapy")

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
stats = Counter()
captured = []


def payload_preview(packet, max_bytes=64):
    """Return a printable preview of the raw payload."""
    if Raw not in packet:
        return None
    data = bytes(packet[Raw].load)[:max_bytes]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{text}  (hex: {data.hex()})"


def tcp_flags(tcp):
    names = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
             "A": "ACK", "U": "URG"}
    return ",".join(names[f] for f in str(tcp.flags) if f in names) or "-"


def handle_packet(packet, show_payload=False):
    captured.append(packet)
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    number = len(captured)

    if ARP in packet:
        stats["ARP"] += 1
        a = packet[ARP]
        op = "request" if a.op == 1 else "reply"
        print(f"[{number}] {ts} ARP {op}: {a.psrc} -> {a.pdst}")
        return

    if IP in packet:
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.proto, f"OTHER({ip.proto})")
        ttl = ip.ttl
    elif IPv6 in packet:
        ip6 = packet[IPv6]
        src, dst = ip6.src, ip6.dst
        proto = PROTO_NAMES.get(ip6.nh, f"OTHER({ip6.nh})")
        ttl = ip6.hlim
    else:
        stats["Other"] += 1
        print(f"[{number}] {ts} Non-IP frame: {packet.summary()}")
        return

    stats[proto] += 1
    line = f"[{number}] {ts} {proto:<5} {src} -> {dst}  len={len(packet)} ttl={ttl}"

    if TCP in packet:
        t = packet[TCP]
        line += f"  ports {t.sport}->{t.dport}  flags={tcp_flags(t)}"
    elif UDP in packet:
        u = packet[UDP]
        line += f"  ports {u.sport}->{u.dport}"
        if DNS in packet and packet[DNS].qd is not None and DNSQR in packet:
            qname = packet[DNSQR].qname.decode(errors="replace")
            line += f"  DNS query: {qname}"
    elif ICMP in packet:
        line += f"  type={packet[ICMP].type} code={packet[ICMP].code}"
    elif ICMPv6EchoRequest in packet:
        line += "  echo request (ping)"
    elif ICMPv6EchoReply in packet:
        line += "  echo reply (ping)"

    print(line)

    if show_payload:
        preview = payload_preview(packet)
        if preview:
            print(f"      payload: {preview}")


def print_summary():
    total = len(captured)
    print("\n" + "=" * 50)
    print(f"Capture summary: {total} packets")
    for name, count in stats.most_common():
        print(f"  {name:<8} {count:>6}  ({count / max(total, 1):.0%})")
    print("=" * 50)


def main():
    p = argparse.ArgumentParser(description="Basic network sniffer (CodeAlpha Task 1)")
    p.add_argument("-i", "--interface", help="interface to sniff on (default: Scapy's default)")
    p.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    p.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 443"')
    p.add_argument("-w", "--write", help="save captured packets to a .pcap file")
    p.add_argument("--payload", action="store_true", help="show a payload preview")
    args = p.parse_args()

    print("Starting capture... press Ctrl+C to stop.\n")
    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            count=args.count,
            prn=lambda pkt: handle_packet(pkt, args.payload),
            store=False,
        )
    except PermissionError:
        sys.exit("Permission denied. Run as root/administrator (e.g. with sudo).")
    except KeyboardInterrupt:
        pass

    print_summary()
    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"Saved {len(captured)} packets to {args.write}")


if __name__ == "__main__":
    main()