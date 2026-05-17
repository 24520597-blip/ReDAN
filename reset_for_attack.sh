#!/bin/bash
# reset_for_attack.sh
# Chạy script này trên TỪNG node để reset về trạng thái vulnerable
# Usage: bash reset_for_attack.sh [server|backbone|openwrt|attacker]

NODE=$1

reset_server() {
    echo "=== RESET SERVER ==="
    # 1. Challenge ACK limit về thấp (dễ cạn)
    sysctl -w net.ipv4.tcp_challenge_ack_limit=1000
    # 2. Clear tất cả iptables
    iptables -F; iptables -X; iptables -t nat -F; iptables -t mangle -F
    # 3. rp_filter off
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
    echo 0 > /proc/sys/net/ipv4/conf/ens33/rp_filter
    # 4. Không rate-limit RST
    sysctl -w net.ipv4.tcp_invalid_ratelimit=0 2>/dev/null
    # 5. Verify
    echo "[+] tcp_challenge_ack_limit = $(sysctl -n net.ipv4.tcp_challenge_ack_limit)"
    echo "[+] rp_filter = $(cat /proc/sys/net/ipv4/conf/all/rp_filter)"
    echo "[+] iptables rules: $(iptables -L | grep -c ACCEPT) ACCEPT rules"
    echo "=== SERVER READY ==="
}

reset_backbone() {
    echo "=== RESET BACKBONE ==="
    # 1. Tắt rp_filter trên tất cả interfaces
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
    echo 0 > /proc/sys/net/ipv4/conf/eth0/rp_filter
    echo 0 > /proc/sys/net/ipv4/conf/eth1/rp_filter
    # 2. Bật ip_forward
    echo 1 > /proc/sys/net/ipv4/ip_forward
    # 3. Clear nftables/iptables
    nft flush ruleset 2>/dev/null
    iptables -F 2>/dev/null; iptables -t nat -F 2>/dev/null
    # 4. Verify
    echo "[+] rp_filter all = $(cat /proc/sys/net/ipv4/conf/all/rp_filter)"
    echo "[+] rp_filter eth0 = $(cat /proc/sys/net/ipv4/conf/eth0/rp_filter)"
    echo "[+] rp_filter eth1 = $(cat /proc/sys/net/ipv4/conf/eth1/rp_filter)"
    echo "[+] ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
    echo "=== BACKBONE READY ==="
}

reset_openwrt() {
    echo "=== RESET OPENWRT NAT ==="
    # 1. rp_filter off
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
    echo 0 > /proc/sys/net/ipv4/conf/eth0/rp_filter
    # 2. Clear extra iptables (giữ NAT masquerade)
    iptables -F FORWARD 2>/dev/null
    iptables -F INPUT 2>/dev/null
    # 3. Thêm route về 2.2.2.0/24 qua Backbone
    ip route add 2.2.2.0/24 via 1.1.1.200 2>/dev/null || true
    # 4. Verify
    echo "[+] rp_filter = $(cat /proc/sys/net/ipv4/conf/all/rp_filter)"
    echo "[+] Route to 2.2.2.0/24: $(ip route show 2.2.2.0/24)"
    echo "=== OPENWRT READY ==="
}

reset_attacker() {
    echo "=== RESET ATTACKER ==="
    # 1. Clear existing iptables
    iptables -F; iptables -X
    # 2. Thêm rule DROP RST (quan trọng để spy hoạt động)
    iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 2.2.2.20 -j DROP
    # 3. rp_filter off
    echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
    # 4. Verify
    echo "[+] iptables RST DROP: $(iptables -L OUTPUT | grep RST)"
    echo "=== ATTACKER READY ==="
}

secure_openwrt() {
    echo "=== BẬT CHẾ ĐỘ PHÒNG THỦ (OPENWRT SECURE MODE) ==="
    # 1. Bật Strict Reverse Path Forwarding (Chống Spoofing)
    echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
    echo 1 > /proc/sys/net/ipv4/conf/eth0/rp_filter
    echo 1 > /proc/sys/net/ipv4/conf/eth1/rp_filter 2>/dev/null
    
    # 2. Khôi phục TCP CLOSE timeout về mức an toàn mặc định (10 giây)
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close=10 2>/dev/null || echo 10 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close
    
    # 3. Verify
    echo "[+] Chống Spoofing (rp_filter) = $(cat /proc/sys/net/ipv4/conf/all/rp_filter) [BẬT]"
    echo "[+] TCP CLOSE timeout = $(cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close 2>/dev/null) giây"
    echo "=== HỆ THỐNG ĐÃ ĐƯỢC BẢO VỆ ==="
}

case $NODE in
    server)         reset_server ;;
    backbone)       reset_backbone ;;
    openwrt)        reset_openwrt ;;
    secure_openwrt) secure_openwrt ;;
    attacker)       reset_attacker ;;
    *)
        echo "Usage: bash reset_for_attack.sh [server|backbone|openwrt|secure_openwrt|attacker]"
        echo ""
        echo "Chạy trên từng node:"
        echo "  Server:   sudo bash reset_for_attack.sh server"
        echo "  Backbone: bash reset_for_attack.sh backbone"
        echo "  OpenWrt:  bash reset_for_attack.sh openwrt"
        echo "  Secure:   bash reset_for_attack.sh secure_openwrt"
        echo "  Attacker: sudo bash reset_for_attack.sh attacker"
        ;;
esac
