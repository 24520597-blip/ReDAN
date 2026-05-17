#!/usr/bin/env python3
# pmtud_nat_detect.py
# Kịch bản mô phỏng Cơ chế phát hiện NAT qua lỗ hổng PMTUD
# (Phần 1 của bài báo ReDAN: Xác định mục tiêu có phải là thiết bị NAT không)

import time
from scapy.all import IP, ICMP, TCP, send, sr1, conf

# Không dùng IP cứng nữa, ta sẽ cho người dùng nhập vào

def detect_nat():
    print("="*60)
    print("🔎 BƯỚC 0: PHÁT HIỆN THIẾT BỊ NAT BẰNG LỖ HỔNG PMTUD")
    print("="*60)
    
    # Yêu cầu nhập thông số
    TARGET_IP = input("Nhập IP mục tiêu cần kiểm tra (Mặc định: 1.1.1.1): ") or "1.1.1.1"
    SERVER_IP = input("Nhập IP máy chủ quan sát (Mặc định: 1.1.1.10): ") or "1.1.1.10"
    try:
        TARGET_PORT = int(input("Nhập Port mục tiêu (Mặc định: 40000): ") or "40000")
        SERVER_PORT = int(input("Nhập Port máy chủ (Mặc định: 8080): ") or "8080")
    except ValueError:
        print("[!] Lỗi: Port phải là số nguyên.")
        return

    print(f"\n[+] Đang thám thính mục tiêu {TARGET_IP} (Giao tiếp với Server {SERVER_IP}:{SERVER_PORT})")
    
    # 1. GỬI GÓI ICMP FRAGMENTATION NEEDED (Thay đổi PMTU của Client)
    print(f"\n[*] BƯỚC 1: Đóng giả Router trung gian, ép mục tiêu giảm MTU xuống 500 bytes.")
    
    # Gói TCP gốc mà mục tiêu đã gửi (cần để gắn vào payload của ICMP Error)
    # Trong thực tế, Attacker sẽ copy header của gói tin bắt được.
    orig_ip_hdr = IP(src=TARGET_IP, dst=SERVER_IP)
    orig_tcp_hdr = TCP(sport=TARGET_PORT, dport=SERVER_PORT, seq=12345)
    
    # Tạo gói báo lỗi ICMP (Type 3, Code 4: Fragmentation Needed)
    # Trường nexthopmtu ép MTU xuống 500
    icmp_err = IP(src=SERVER_IP, dst=TARGET_IP) / ICMP(type=3, code=4, nexthopmtu=500) / orig_ip_hdr / orig_tcp_hdr
    
    send(icmp_err, verbose=0)
    print("    -> Đã gửi thông báo lỗi ICMP (Fragmentation Needed) tới mục tiêu.")
    print("    (Nếu mục tiêu là NAT, nó sẽ forward lỗi này vào Client bên trong)")
    
    time.sleep(1)
    
    # 2. KIỂM TRA PHẢN ỨNG CỦA BẢN THÂN ĐỊA CHỈ IP ĐÓ (Ping 1500 bytes)
    print("\n[*] BƯỚC 2: Ping mục tiêu với gói tin 1500 bytes để đo MTU thực tế của nó.")
    
    # Gửi gói ICMP Echo Request lớn (1000 bytes payload + headers ~ 1028 bytes)
    # Lớn hơn mức MTU 500 mà ta vừa ép.
    large_ping = IP(dst=TARGET_IP) / ICMP() / (b"X" * 1000)
    
    print("    -> Đang đợi ICMP Echo Reply...")
    reply = sr1(large_ping, timeout=2, verbose=0)
    
    if reply:
        reply_len = len(reply[IP])
        print(f"    -> Nhận được phản hồi: Độ dài gói tin = {reply_len} bytes.")
        
        if reply_len > 500:
            print("\n[!] KẾT LUẬN: ĐÂY LÀ THIẾT BỊ NAT!")
            print("    Giải thích: Địa chỉ IP này đã gửi trả một gói tin nguyên vẹn > 500 bytes.")
            print("    Điều này chứng tỏ lệnh giảm MTU lúc nãy đã bị đẩy cho máy Client bên trong,")
            print("    còn bản thân Hệ điều hành của địa chỉ IP này KHÔNG bị ảnh hưởng PMTUD.")
        else:
            print("\n[!] KẾT LUẬN: ĐÂY LÀ MÁY CHỦ ĐỘC LẬP (Standalone Host)!")
            print("    Giải thích: Nó đã tự phân mảnh gói tin xuống dưới 500 bytes.")
    else:
        print("\n[-] Không nhận được phản hồi. Mục tiêu có thể chặn Ping.")

if __name__ == "__main__":
    detect_nat()
