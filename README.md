# ReDAN (CVE-2016-5696) - Off-Path NAT DoS Attack Lab

Dự án này mô phỏng cuộc tấn công từ chối dịch vụ (DoS) nhắm vào các bộ định tuyến NAT bằng cách lợi dụng lỗ hổng **TCP Challenge ACK (CVE-2016-5696)** kết hợp với cơ chế **NAT Conntrack Loose Tracking**.

Đây là mô hình tấn công **Off-Path (Blind Attack)**: Kẻ tấn công không cần (và không thể) đứng ở giữa đường truyền để nghe lén gói tin (Man-in-the-Middle) nhưng vẫn có thể ngắt kết nối TCP của nạn nhân.

---

## 1. Mô hình Mạng (Topology)
Cần thiết lập 5 máy ảo (VM) trong VMware/VirtualBox với cấu trúc mạng như sau để mô phỏng hoàn chỉnh môi trường Internet thực tế:

*   **Server (1.1.1.10)**: Máy chủ dịch vụ đích.
*   **Backbone Router (1.1.1.200 & 2.2.2.200)**: Bộ định tuyến lõi kết nối giữa mạng của Attacker (2.2.2.x) và mạng của Server/OpenWrt (1.1.1.x).
*   **OpenWrt Router (WAN: 1.1.1.1, LAN: 192.168.1.1)**: Bộ định tuyến Gateway thực hiện NAT (Masquerade) cho Client.
*   **Client (192.168.1.10)**: Máy tính nạn nhân nằm ở mạng LAN sau NAT.
*   **Attacker (2.2.2.20)**: Máy tấn công nằm ở một dải mạng hoàn toàn khác biệt, kết nối vào mạng mục tiêu thông qua Backbone Router. Đảm bảo tính chất Off-Path nghiêm ngặt.

---

## 2. Chuẩn bị & Cài đặt thư viện

Trên máy **Attacker**, bạn cần cài đặt thư viện `scapy` để chế tạo và gửi gói tin giả mạo.

```bash
sudo apt update
sudo apt install -y python3 python3-pip iptables
sudo pip3 install scapy
```

---

## 3. Cấu hình Môi trường (Reset Scripts)

Lỗ hổng yêu cầu hệ điều hành phải ở một số cấu hình mặc định (hoặc vulnerable) nhất định. Bạn cần chạy script `reset_for_attack.sh` trên từng máy ảo trước khi bắt đầu bài Lab:

*   **Trên Server**: Hạ giới hạn TCP Challenge ACK xuống 5 (hoặc 1000 cho các chuẩn nhân Linux cũ) và tắt Reverse Path Filter.
    ```bash
    sudo bash reset_for_attack.sh server
    ```
*   **Trên Backbone Router**: Tắt chặn IP giả mạo và bật chuyển tiếp gói tin (ip_forward).
    ```bash
    sudo bash reset_for_attack.sh backbone
    ```
*   **Trên OpenWrt (NAT)**: Tắt kiểm tra IP giả mạo (rp_filter) và cấu hình Route ngược về phía Attacker.
    ```bash
    bash reset_for_attack.sh openwrt
    ```
*   **Trên Attacker**: Cài đặt rule Tường lửa ngăn hệ điều hành tự động gửi RST phá hỏng "Spy Connection".
    ```bash
    sudo bash reset_for_attack.sh attacker
    ```

---

## 4. Khởi chạy Dịch Vụ (Mục tiêu & Nạn nhân)

1.  **Mở Terminal trên Server**, khởi chạy máy chủ nhận kết nối (Lắng nghe cổng 8080):
    ```bash
    python3 server.py
    ```
2.  **Mở Terminal trên Client**, khởi chạy tập lệnh giả lập Nạn nhân. Client sẽ tạo nhiều kết nối đến Server và gửi Heartbeat mỗi 5 giây:
    ```bash
    python3 client.py
    ```

> *Lưu ý: Lúc này bạn sẽ thấy Server và Client trò chuyện với nhau bình thường. Hãy giữ nguyên 2 cửa sổ này để quan sát kết quả tấn công.*

---

## 5. Thực thi Tấn Công (Attacker)

Mở Terminal trên máy **Attacker**, chạy script với quyền `sudo` (bắt buộc vì dùng Raw Sockets):

```bash
sudo python3 attacker.py
```

*Tip: Nếu bạn chỉ muốn test khả năng ngắt kết nối mà bỏ qua giai đoạn 1 (quét dò tìm mất nhiều thời gian), hãy thêm cờ `--skip-scan`.*

### Quá trình tấn công sẽ tự động diễn ra qua 3 Giai đoạn (Stages):

*   **[Stage 1] ORACLE DISCOVERY (Dò tìm Port NAT):** 
    Attacker tạo một kết nối mồi (Spy Connection) đến Server. Bằng cách lợi dụng giới hạn bộ đếm (Rate Limit) của gói tin Challenge ACK (CVE-2016-5696), Attacker gửi hàng loạt SYN-ACK giả mạo để "dò mìn". Nếu đoán trúng Port của Client đang mở, Server sẽ trừ đi 1 Challenge ACK, khiến Spy Connection không nhận được gói ACK cuối cùng. Attacker dựa vào sự sụt giảm này để tìm ra chính xác Ephemeral Port (Port ảo) mà NAT cấp phát cho Client.
    
*   **[Stage 2] NAT TEARDOWN (Đánh sập bảng NAT):** 
    Khi đã biết Port, Attacker tiến hành "Brute-force" (thử sai) dãy số Sequence Number trong không gian 4 tỷ bằng các gói `RST+ACK` giả mạo. Mục tiêu là để một gói lọt vào cửa sổ (TCP Window). Router OpenWrt khi thấy gói tin này sẽ ngay lập tức **xóa bỏ trạng thái của kết nối trong bảng `nf_conntrack`** (Đưa về trạng thái CLOSE).

*   **[Stage 3] CARPET BOMBING (Rải thảm chống hồi sinh):** 
    Nhờ cơ chế *TCP Loose Tracking* mặc định của bộ định tuyến, khi bảng NAT bị xóa, một gói tin Heartbeat của Client vẫn có thể đánh lừa NAT tự động hồi sinh kết nối (Resurrect). Để triệt tiêu hoàn toàn sự hồi sinh này, Attacker tiến hành **Carpet Bombing**: Sử dụng socket L3 tốc độ siêu cao quét liên tục dãy Sequence Number bằng các gói RST giả mạo, ép chặt kết nối không cho Client ngóc đầu lên. 

---

## 6. Kết Quả Mong Đợi

*   **Trên màn hình Client (`client.py`)**: 
    Kết nối đang hoạt động sẽ bất ngờ bị văng ra kèm thông báo lỗi:
    `[-] S1 error timed out` 
    hoặc 
    `[-] S1 RST (TCP reset by attacker)`
    Và Client sẽ liên tục thất bại trong nỗ lực Reconnect.
    
*   **Trên màn hình Server (`server.py`)**: 
    Server không thể nhận được gói Heartbeat và sẽ in ra thông báo `[!] Timeout` rồi đóng hoàn toàn phiên làm việc của nạn nhân.

Cuộc tấn công ReDAN hoàn tất xuất sắc!
