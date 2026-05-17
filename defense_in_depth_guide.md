# HƯỚNG DẪN TRIỂN KHAI PHÒNG THỦ CHIỀU SÂU (DEFENSE IN DEPTH) CHỐNG REDAN

Tài liệu này trình bày kiến trúc phòng thủ 5 lớp (Defense in Depth) nhằm chống lại các kỹ thuật tấn công Off-Path TCP (đặc biệt là lỗ hổng CVE-2016-5696 được sử dụng trong ReDAN).

Mục tiêu cốt lõi của mô hình này không chỉ là ngăn chặn kẻ tấn công mà còn là **bảo vệ trải nghiệm người dùng (UX)**, đảm bảo hệ thống vận hành trơn tru ngay cả khi đang bị nhắm mục tiêu.

---

## 🛡️ LỚP 1: KERNEL TCP HARDENING (Triển khai tại Server)
*Mục tiêu: Vá triệt để lỗ hổng rò rỉ Side-channel ở nhân hệ điều hành.*

**Cấu hình (`sysctl`):**
```bash
# 1. Nâng cực hạn và ngẫu nhiên hóa bộ đếm Challenge ACK (Vá gốc CVE-2016-5696)
sysctl -w net.ipv4.tcp_challenge_ack_limit=2147483647

# 2. Ngăn chặn RST Injection vào các socket đang ở trạng thái TIME-WAIT
sysctl -w net.ipv4.tcp_rfc1337=1

# 3. Kích hoạt SYN Cookies để chống tấn công cạn kiệt tài nguyên (SYN Flood)
sysctl -w net.ipv4.tcp_syncookies=1
```
> **Đánh đổi (Trade-off):** Gần như không ảnh hưởng đến UX. Sự thay đổi chỉ diễn ra ẩn bên trong cách Kernel xử lý cờ TCP.

---

## 🛡️ LỚP 2: NAT DEVICE HARDENING (Triển khai tại Router/OpenWRT)
*Mục tiêu: Ngăn chặn Router dễ dãi chấp nhận gói tin dị thường và xáo trộn sơ đồ cổng mạng.*

**Cấu hình (`iptables` & `sysctl`):**
```bash
# 1. Strict Conntrack: Không chấp nhận các gói tin (như RST) nằm ngoài Window TCP hợp lệ
sysctl -w net.netfilter.nf_conntrack_tcp_loose=0

# 2. Randomize Port Mapping: Buộc NAT phải xáo trộn hoàn toàn Port nguồn (Chống dò Port)
iptables -t nat -A POSTROUTING -j MASQUERADE --random-fully

# 3. Rate Limit SYN-ACK: Cản trở quá trình Dò quét Cổng (Port Discovery)
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -j DROP
```
> **Đánh đổi (Trade-off):** Việc thiết lập `tcp_loose=0` có thể vô tình làm rớt các gói tin hợp lệ trong những kịch bản Mạng chuyển đổi dự phòng (NAT Failover/Asymmetric Routing). Cần kiểm thử kỹ lưỡng.

---

## 🛡️ LỚP 3: NETWORK-LEVEL FILTERING (Triển khai tại Edge Router)
*Mục tiêu: Chặn đứng nguồn lưu lượng giả mạo ngay tại cửa ngõ.*

**Cấu hình (`sysctl` & `iptables`):**
```bash
# 1. Bật Strict uRPF: Chặn toàn bộ các gói tin mang địa chỉ IP nguồn giả mạo (Spoofed IP)
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.eth0.rp_filter=1

# 2. Rate Limit RST: Chặn "Carpet Bombing" (Thả thảm RST) từ bên ngoài
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 5/s --limit-burst 10 -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
```
> **Đánh đổi (Trade-off):** Limit RST quá chặt có thể làm chậm quá trình đóng kết nối của các Session thực sự bị lỗi mạng, gây ra hiện tượng "treo" nhẹ (dangling sockets), ảnh hưởng nhỏ đến UX.

---

## 🛡️ LỚP 4: APPLICATION LAYER (Triển khai tại Server App)
*Mục tiêu: Theo dõi hành vi bất thường và tự động cảnh báo (Alerting) dựa trên sự cố ngắt kết nối.*

Việc đếm gói RST ở tầng Application (Python/NodeJS) là không khả thi vì Kernel đã chặn luồng. Thay vào đó, Ứng dụng sẽ phát hiện hiện tượng **"Connection Flapping"** (Đứt kết nối liên tục).

**Mã giả (Python):**
```python
import time
from collections import defaultdict

# Lưu trữ lịch sử đứt kết nối của từng IP
disconnect_tracker = defaultdict(list)

def on_client_disconnect(client_ip, error_type):
    if error_type in ("ConnectionResetError", "BrokenPipeError"):
        now = time.time()
        # Chỉ giữ lại các bản ghi trong vòng 10 giây qua
        disconnect_tracker[client_ip] = [t for t in disconnect_tracker[client_ip] if now - t < 10]
        disconnect_tracker[client_ip].append(now)
        
        # Nếu đứt kết nối > 5 lần trong 10 giây -> Báo động DoS
        if len(disconnect_tracker[client_ip]) > 5:
            trigger_alert(f"[CRITICAL] Có dấu hiệu Tấn công cắt đứt kết nối (RST Injection/DoS) nhắm vào {client_ip}")
```

---

## 🛡️ LỚP 5: ENCRYPTION & PROTOCOL SHIFT (TLS / HTTP3)
*Mục tiêu: Đây là lớp phòng thủ tối thượng, giải quyết triệt để vấn đề UX.*

1. **QUIC / HTTP3 (UDP):** 
   - ReDAN khai thác lỗ hổng trong cỗ máy trạng thái của TCP. Giao thức QUIC (nền tảng của HTTP/3) chạy trên **UDP**. Việc chuyển dịch sang QUIC khiến ứng dụng hoàn toàn **miễn nhiễm 100%** với TCP RST Injection. Kẻ tấn công sẽ trở nên vô dụng.
   
2. **TLS Session Resumption (Khôi phục phiên mã hóa):**
   - Nếu bắt buộc phải dùng TCP, TLS 1.3 cung cấp cơ chế Session Tickets (Vé phiên). Nếu Kẻ tấn công cắt đứt được TCP (gây rớt mạng), Ứng dụng Client sẽ tự động mở lại một luồng TCP mới và gửi Ticket để khôi phục trạng thái cũ ngay lập tức (0-RTT).
   - *Kết quả:* UX được duy trì ở mức xuất sắc, người dùng chỉ cảm thấy mạng bị trễ khoảng vài trăm mili-giây và quá trình reconnect diễn ra hoàn toàn vô hình (Transparent).
