#!/bin/sh
# ============================================
#  auto_config_openwrt_ReDAN.sh
#  Cấu hình OpenWrt 22.03 cho lab ReDAN
#  KHÔNG cần Internet, không cài thêm gói
# ============================================

set -e

echo "=== ReDAN Lab - OpenWrt Auto Setup (no opkg) ==="
echo "WARNING: This script will overwrite network/firewall config!"
echo "Press Ctrl+C within 5s to abort..."
sleep 5

# 1. Cấu hình network interfaces
echo "[1/4] Writing /etc/config/network..."
cat > /etc/config/network << 'EOF'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config interface 'wan'
	option device 'eth0'
	option proto 'static'
	option ipaddr '1.1.1.1'
	option netmask '255.255.255.0'

config interface 'lan'
	option device 'eth1'
	option proto 'static'
	option ipaddr '192.168.1.1'
	option netmask '255.255.255.0'
EOF

echo "Restarting network..."
/etc/init.d/network restart
sleep 5

# 2. Bật NAT masquerade
echo "[2/4] Enabling masquerade on WAN zone..."
uci set firewall.@zone[1].masq='1'
uci commit firewall
/etc/init.d/firewall restart

# 3. Bật nf_conntrack_tcp_loose (temporary + permanent)
echo "[3/4] Enabling tcp_loose mode..."
echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_loose
if ! grep -q "nf_conntrack_tcp_loose" /etc/sysctl.conf; then
    echo "net.netfilter.nf_conntrack_tcp_loose=1" >> /etc/sysctl.conf
fi

# 4. Kiểm tra
echo "[4/4] Verifying configuration..."
echo ""
echo "Network interfaces:"
ip -4 addr show eth0; ip -4 addr show eth1
echo ""
echo "Firewall masquerade status:"
uci show firewall | grep masq
echo ""
echo "Conntrack loose mode:"
cat /proc/sys/net/netfilter/nf_conntrack_tcp_loose
echo ""
echo "Bảng conntrack hiện tại (cổng 8080):"
cat /proc/net/nf_conntrack 2>/dev/null | grep 8080 || echo "(chưa có kết nối tới server)"
echo ""
echo "=== Setup complete! ==="
echo "Now start server, client, then attacker."
