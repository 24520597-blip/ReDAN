# Báo Cáo Phân Tích Kỹ Thuật: Luồng Thực Thi Tấn Công ReDAN NAT

Tài liệu này trình bày chi tiết về luồng thực thi, các bước triển khai, nguyên lý hoạt động và đề xuất phòng thủ chống lại mô hình tấn công **ReDAN (Remote DoS Against NAT Networks)** trong khuôn khổ đồ án.

---

## 1. Tổng Quan Về Đồ Án

Đồ án này xây dựng một mô hình mạng ảo hóa để kiểm chứng lỗ hổng ReDAN (được công bố tại hội nghị NDSS 2025). Mô hình bao gồm 4 thành phần chính:

*   **Client (192.168.1.10):** Đóng vai trò là nạn nhân, nằm trong mạng nội bộ (LAN) sau thiết bị NAT. Client liên tục duy trì kết nối TCP (gửi tín hiệu Heartbeat) đến máy chủ.
*   **Router NAT (1.1.1.1):** Thiết bị định tuyến biên dịch địa chỉ mạng (OpenWrt/pfSense), duy trì bảng trạng thái kết nối (`nf_conntrack`) để chuyển tiếp gói tin giữa Client và Server.
*   **Server (1.1.1.10:8080):** Máy chủ TCP hợp lệ nằm trên mạng Internet (Public).
*   **Attacker (2.2.2.20):** Kẻ tấn công nằm trên mạng riêng biệt VMnet12 (`2.2.2.0/24`), hoàn toàn tách biệt khỏi Server (VMnet10) và Client (VMnet8). Mọi gói tin tấn công đều được định tuyến (route) qua interface VMnet12 của Router OpenWrt (`2.2.2.1`) để đến mạng Public. Kẻ tấn công hoạt động hoàn toàn **Off-path** — không nằm trên đường truyền vật lý giữa Client và Server, nhưng vẫn có khả năng phá vỡ kết nối thông qua kỹ thuật giả mạo IP (IP Spoofing) và side-channel.

**Mục tiêu của cuộc tấn công:**
1.  Ngắt kết nối TCP hợp lệ hiện có giữa Client và Server.
2.  Chặn hoàn toàn quyền truy cập, khiến Client không thể thiết lập lại kết nối mới (DoS vô thời hạn).

---

## 2. Chi Tiết Luồng Thực Thi (Kẻ Tấn Công Đã Làm Những Gì?)

Luồng thực thi trong mã nguồn `attacker.py` được chia làm 4 giai đoạn chính nối tiếp nhau. Điểm đặc biệt của cuộc tấn công này là kẻ tấn công hoạt động hoàn toàn **off-path** — không cần ở trên đường truyền hay nghe lén bất kỳ gói tin nào của nạn nhân.

### Phase 0: Thiết Lập Spy Connection (Oracle Setup)
*   **Hành động:** Kẻ tấn công tạo một kết nối TCP **hợp pháp** của riêng mình đến Server.
*   **Cách thức thực hiện:** Từ IP thật (`2.2.2.20` trên VMnet12), Attacker thực hiện bắt tay 3 bước (3-way handshake) với Server (`1.1.1.10:8080`) bằng thư viện `scapy`. Gói tin được định tuyến qua OpenWrt Router (`2.2.2.1` → `1.1.1.1`) để đến Server. Kết nối này hoàn toàn độc lập, không đi qua NAT masquerade, và không liên quan gì đến phiên làm việc của Client.
*   **Mục đích:** Kết nối này đóng vai trò làm **"kênh tham chiếu" (Oracle)** — một công cụ đo lường gián tiếp. Thông qua nó, Attacker có thể thăm dò trạng thái bộ đếm `tcp_challenge_ack_limit` trên kernel của Server. Nếu bộ đếm bị cạn kiệt (do Challenge ACK được gửi cho port khác), Spy Connection sẽ không nhận được phản hồi ACK, qua đó **tiết lộ gián tiếp** rằng port đích có kết nối đang hoạt động.

### Stage 1: Phát Hiện Port NAT (Challenge ACK Side-Channel — CVE-2016-5696)
*   **Hành động:** Quét từng port trong dải ephemeral để tìm port NAT đang hoạt động.
*   **Cách thức thực hiện:**
    1.  Với mỗi port ứng viên (`xs`), Attacker giả mạo IP của NAT (`1.1.1.1`) gửi hàng loạt gói **SYN-ACK giả mạo** (spoofed) đến Server trên port `xs`.
    2.  Nếu port `xs` thực sự có kết nối TCP đang hoạt động (của Client qua NAT), Server sẽ coi gói SYN-ACK là bất thường và phản hồi bằng các gói **Challenge ACK** theo chuẩn RFC 5961. Mỗi Challenge ACK tiêu hao 1 đơn vị trong bộ đếm `tcp_challenge_ack_limit` (kernel giới hạn tối đa 1000/giây).
    3.  Nếu port `xs` không có kết nối, Server đơn giản gửi RST (không ảnh hưởng bộ đếm).
    4.  Ngay sau đó, Attacker **thăm dò Spy Connection**: gửi một gói SYN có SEQ lệch trên kênh oracle. Nếu không nhận được Challenge ACK → bộ đếm đã cạn kiệt → port `xs` **tồn tại kết nối thật**.
*   **Mục đích:** Xác định chính xác Port NAT ngẫu nhiên (`xs`) mà NAT đang mở để đại diện cho Client, mà **hoàn toàn không cần sniff hay nghe lén** bất kỳ gói tin nào trên đường truyền.

> **Ghi chú Lab:** Trong môi trường thí nghiệm, dải port Client được thu hẹp về `40000–40010` (bằng lệnh `sysctl net.ipv4.ip_local_port_range`) để giảm thời gian quét. Trong thực tế, Attacker sẽ phải quét toàn bộ dải ephemeral (`32768–61000`, ~28.000 ports).

### Stage 2: Phá Hủy Kết Nối (RST Brute-Force 2 Hướng)
*   **Hành động:** Gửi gói TCP Reset giả mạo để xóa sổ kết nối ở cả NAT và Server.
*   **Cách thức thực hiện:** Kẻ tấn công tiến hành brute-force trên 65.536 giá trị Sequence Number (chia đều không gian 2³² = ~4 tỷ), gửi gói TCP mang cờ **RST** theo **2 hướng** đồng thời:
    1.  **Hướng 1 (Server→NAT):** Giả mạo IP Server (`1.1.1.10`), gửi RST về phía NAT (`1.1.1.1`) trên port `xs`. Mục tiêu: Lừa NAT tin rằng Server đã chủ động ngắt kết nối → NAT xóa bản ghi `nf_conntrack`.
    2.  **Hướng 2 (NAT→Server):** Giả mạo IP NAT (`1.1.1.1`), gửi RST lên Server (`1.1.1.10`) trên port 8080. Mục tiêu: Lừa Server tin rằng Client (qua NAT) đã hủy kết nối → Server đóng socket.
*   **Mục đích:** Chỉ cần 1 trong 65.536 giá trị SEQ rơi vào cửa sổ chấp nhận (Receive Window) của đích, gói RST sẽ được chấp nhận. Do thiết bị NAT với cấu hình `tcp_loose=1` thường **bỏ qua kiểm tra SEQ đối với gói RST**, xác suất thành công rất cao. Kết quả: Đường hầm NAT bị cắt đứt, socket Server bị đóng — kết nối TCP bị hủy hoàn toàn ở cả 2 đầu.

### Stage 3: Chặn Tái Kết Nối Vô Thời Hạn (Carpet-Bombing)
*   **Hành động:** Dội bom rải thảm toàn bộ các port trong dải ephemeral.
*   **Cách thức thực hiện:** Attacker kích hoạt vòng lặp vô hạn, liên tục bắn các gói **RST** (với SEQ ngẫu nhiên, 30 gói/port/lượt) vào toàn bộ dải port đã cấu hình của NAT. Gói tin được gửi theo 2 hướng (Server→NAT và NAT→Server) giống Stage 2.
*   **Mục đích:** Cứ mỗi lần Client thử kết nối lại (gửi SYN), NAT sẽ phải mở một port mới. Nhưng vì cơn mưa rải thảm RST liên tục dội vào, port mới vừa cấp sẽ bị "bắn hạ" (xóa conntrack) ngay tức khắc trước khi quá trình bắt tay 3 bước (3-way handshake) kịp hoàn thành. Client bị từ chối dịch vụ (DoS) vĩnh viễn cho đến khi tắt tool tấn công.

> **Ghi chú Lab:** Trong môi trường thí nghiệm, carpet-bombing chỉ phủ 11 ports (`40000–40010`). Trong triển khai thực tế trên Internet, kẻ tấn công sẽ rải thảm toàn bộ dải `32768–61000` (~28.000 ports), tạo ra lưu lượng khoảng ~5.7 MB/s (~28.000 gói/giây).

---

## 3. Tại Sao Có Thể Làm Được? Dựa Trên Nguyên Tắc Nào?

Toàn bộ chuỗi tấn công (Vulnerability Chain) này thành công nhờ vào việc khai thác một cách khéo léo **những lỗ hổng trong thiết kế giao thức** và **sự đánh đổi hiệu năng** của các thiết bị mạng hiện đại:

**1. Sự Lỏng Lẻo Trong Xử Lý Trạng Thái Của Thiết Bị NAT (NAT State Looseness)**
Theo lý thuyết (RFC 5961), việc ngắt một phiên TCP bằng gói RST yêu cầu hệ thống phải kiểm tra cực kỳ chặt chẽ số Sequence Number. Nếu sai dù chỉ 1 đơn vị, gói tin phải bị loại bỏ.
Tuy nhiên, trong thực tế, để tối ưu hóa năng lực CPU và tốc độ định tuyến băng thông cao, các thiết bị NAT (đặc biệt là tường lửa sử dụng `netfilter` trên Linux với cấu hình `tcp_loose=1`) thường **bỏ qua việc kiểm tra Sequence Number đối với gói RST**. Chỉ cần IP đích, IP nguồn và Port trùng khớp là Router NAT sẽ tin tưởng và thẳng tay xóa bản ghi `conntrack`.

**2. Lỗ Hổng Rò Rỉ Trạng Thái Qua TCP Challenge ACK (RFC 5961)**
Tính năng Challenge ACK ban đầu được tổ chức IETF tạo ra để vá lỗi chống lại dạng tấn công *Blind Spoofing* (đoán mò số thứ tự Sequence). Nguyên tắc là: Thay vì im lặng vứt bỏ một gói tin TCP có SEQ sai lệch, máy chủ phải gửi lại một gói ACK chứa thông tin SEQ hợp lệ để hai bên "đồng bộ" lại.
Trớ trêu thay, chính cơ chế phòng vệ này lại trở thành một lỗ hổng rò rỉ thông tin (side-channel). Kẻ tấn công chỉ cần "gõ cửa" Server bằng một gói tin rác, Server sẽ thật thà "đọc pass" (gửi Challenge ACK chứa Sequence Number thật). Có được thông tin này, việc ngắt kết nối Server trở nên cực kỳ dễ dàng.

**3. Thiếu Cơ Chế Lọc IP Giả Mạo (Anti-Spoofing / BCP38)**
Cả quá trình tấn công phụ thuộc hoàn toàn vào việc Kẻ tấn công (Attacker) có thể tự do đóng giả (IP Spoofing) làm địa chỉ của Server (khi đánh NAT) và địa chỉ của NAT (khi đánh Server). Vì mạng Public thường không có hoặc không cấu hình chặt chẽ các luật chống giả mạo IP (BCP38), các gói tin giả tự do vượt qua các bộ định tuyến để đến được đích.

---

## 4. Phương Pháp Đo Lường Ảnh Hưởng (Impact Assessment)

Để hoàn thành yêu cầu đánh giá độ sát thương của tấn công trên Router Linux/pfSense, dưới đây là các chỉ số đo lường trong đồ án:

### 4.1. Đo lường Connection Failure (Tỷ lệ đứt kết nối)
*   **Cách thức:** Quan sát log đầu ra (Output) của tiến trình `client.py`.
*   **Đánh giá:** Ghi nhận sự xuất hiện của các ngoại lệ `ConnectionResetError` (do Stage 2 — RST brute-force) và `ConnectionRefusedError` (do Server đã đóng socket). Khi kịch bản tiến vào Stage 3 (Carpet-Bombing), tỷ lệ Connection Failure đạt **100%** (Downtime hoàn toàn) do client liên tục bị từ chối bắt tay 3 bước.

### 4.2. Đo lường Packet Loss (Tỷ lệ mất gói tin)
*   **Cách thức:** Chạy lệnh `ping 1.1.1.10 -i 0.5` liên tục từ Client đến Server trong lúc cuộc tấn công diễn ra.
*   **Đánh giá:** Ở các giai đoạn ngắt kết nối tĩnh (Stage 1 và 2), Ping vẫn có thể hoạt động vì ICMP không bị nhắm mục tiêu trực tiếp. Tuy nhiên, khi chuyển sang Stage 3 (Carpet-Bombing), lượng gói tin RST ồ ạt tác động vào bộ định tuyến làm nghẽn bảng NAT. Dù băng thông tấn công thấp, sự xáo trộn liên tục của bảng `conntrack` có thể làm rớt các gói tin Ping hợp lệ đang đi qua, thể hiện qua các dòng `Request Timeout`. Kết quả đo lường là tỉ lệ `% packet loss` gia tăng sau cuộc tấn công.

### 4.3. Đo lường Latency (Độ trễ) và Tài nguyên Router
*   **Cách thức:** Sử dụng công cụ `htop` hoặc `top -d 1` trên máy Router OpenWrt để theo dõi mức chiếm dụng CPU, kết hợp thời gian phản hồi `time=...ms` từ lệnh Ping của Client.
*   **Đánh giá:** Dù cuộc tấn công tốn băng thông rất thấp (~5.7MB/s), nhưng số lượng gói tin phải xử lý trên giây (PPS - Packet Per Second) là rất lớn (~28.000 gói/giây). Điều này làm CPU của Router vọt lên xử lý các **ngắt phần cứng (CPU Interrupts - hi/si)** liên tục để đối chiếu bảng NAT. Càng nhiều tài nguyên CPU bị chiếm dụng, độ trễ xử lý gói tin (Latency) của người dùng hợp lệ càng kéo dài.

---

## 5. Đề Xuất Quy Tắc Phòng Thủ (Mitigation Rules & Rate Limiting)

Để bảo vệ Router Linux/pfSense khỏi mô hình tấn công ReDAN, đồ án đề xuất các giải pháp kỹ thuật cụ thể tác động vào bộ nhớ hạt nhân và tường lửa:

### 5.1. Siết chặt quản lý trạng thái TCP (Fix TCP Window Tracking)
Lỗ hổng cốt lõi giúp ReDAN thành công nằm ở việc Router Linux quá dễ dãi khi đánh giá độ tin cậy của các gói RST. Ta cần vô hiệu hóa cơ chế này.
*   **Giải pháp (Lệnh Sysctl):**
    ```bash
    sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
    ```
*   **Tác dụng:** Buộc hệ điều hành phải đối chiếu khắt khe Sequence Number và Window Size của mọi gói tin RST với phiên làm việc thực tế. Gói tin giả mạo mù quáng từ Attacker sẽ bị vứt bỏ (Drop) ngay từ cửa ngõ vì sai lệch Sequence.

### 5.2. Chống IP Spoofing (Reverse Path Filtering - BCP38)
Kẻ tấn công đóng giả IP từ hướng mạng công cộng để gửi lệnh rác. Ta cần ngăn chặn việc mạo danh địa chỉ.
*   **Giải pháp (Lệnh Sysctl):**
    ```bash
    sysctl -w net.ipv4.conf.all.rp_filter=1
    ```
*   **Tác dụng:** Kích hoạt xác thực uRPF (Unicast Reverse Path Forwarding). Nếu một gói tin đi vào cổng WAN mà mang địa chỉ IP gốc của cổng LAN (hoặc địa chỉ không hợp lệ), Router sẽ tự động ném bỏ gói tin vì không phù hợp với bảng định tuyến.

### 5.3. Giới hạn tốc độ ICMP (Rate Limiting Stage 1)
Phòng chống kẻ tấn công lợi dụng thông điệp ICMP báo lỗi để đầu độc thiết lập PMTU hoặc lừa NAT xóa bảng theo dõi.
*   **Giải pháp (Rule Iptables):**
    ```bash
    iptables -A INPUT -p icmp --icmp-type port-unreachable -m limit --limit 1/s -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type port-unreachable -j DROP
    ```
*   **Tác dụng:** Giới hạn số lượng gói ICMP loại 3 chỉ được phép xử lý tối đa 1 gói mỗi giây, cắt đứt hoàn toàn khả năng xả rác ICMP dội bom.

### 5.4. Giới hạn tần suất tạo Port (Rate Limiting SYN)
Ngăn chặn sức sát thương của Stage 4 (Carpet-Bombing), vốn có khả năng làm kiệt quệ tài nguyên cấp phát Port động.
*   **Giải pháp (Rule Iptables):**
    ```bash
    iptables -I FORWARD -p tcp --syn -m limit --limit 20/s --limit-burst 50 -j ACCEPT
    iptables -A FORWARD -p tcp --syn -j DROP
    ```
*   **Tác dụng:** Ngay cả khi bộ nhớ NAT bị Attacker cố tình tẩy xóa, Client nội bộ cũng chỉ được phép gửi tối đa 20 yêu cầu kết nối TCP mới mỗi giây. Giải pháp này giúp Router không bị sập CPU do phải cập nhật bảng trạng thái `nf_conntrack` dồn dập.
