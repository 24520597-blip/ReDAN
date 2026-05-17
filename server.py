"""
server.py — Victim Server
IP: 1.1.1.10  Port: 8080
Chạy: python3 server.py
"""

import socket
import threading
import time
from collections import defaultdict

SERVER_IP   = "1.1.1.10"
SERVER_PORT = 8080

active_connections = {}   # { (ip, port): socket }
lock = threading.Lock()

# 🛡️ TẦNG 4: APPLICATION DEFENSE (Theo dõi hành vi đứt kết nối)
disconnect_tracker = defaultdict(list)

def trigger_alert(client_ip):
    print("\n" + "!"*60)
    print(f" [CRITICAL ALERT] PHÁT HIỆN TẤN CÔNG DoS / RST INJECTION!")
    print(f" Mục tiêu IP bị tấn công: {client_ip}")
    print(f" Hành vi: Đứt kết nối (RST) liên tục bất thường.")
    print("!"*60 + "\n")

# ─────────────────────────────────────────
def handle_client(conn, addr):
    client_ip = addr[0]
    with lock:
        active_connections[addr] = conn
        print(f"[+] Connected   : {addr[0]}:{addr[1]}  |  total={len(active_connections)}")

    try:
        while True:
            conn.settimeout(60)
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(b"ACK:" + data)
    except socket.timeout:
        print(f"[!] Timeout      : {addr}")
    except ConnectionResetError:
        print(f"[!] RST received : {addr}  ← socket torn down by attack")
        # --- THỰC THI LỚP PHÒNG THỦ SỐ 4 ---
        with lock:
            now = time.time()
            # Giữ lại các lần đứt kết nối trong 10 giây qua
            disconnect_tracker[client_ip] = [t for t in disconnect_tracker[client_ip] if now - t < 10]
            disconnect_tracker[client_ip].append(now)
            
            # Cảnh báo nếu > 3 lần trong 10 giây
            if len(disconnect_tracker[client_ip]) > 3:
                trigger_alert(client_ip)
                # Reset bộ đếm để không spam log
                disconnect_tracker[client_ip] = []
    except Exception as e:
        print(f"[!] Error        : {addr} — {e}")
    finally:
        with lock:
            active_connections.pop(addr, None)
            print(f"[-] Disconnected: {addr}  |  total={len(active_connections)}")
        conn.close()

# ─────────────────────────────────────────
def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((SERVER_IP, SERVER_PORT))
    srv.listen(10)
    print(f"[*] Victim Server listening on {SERVER_IP}:{SERVER_PORT}")
    print(f"[*] Waiting for clients...\n")

    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"[!] Accept error: {e}")

if __name__ == "__main__":
    start_server()