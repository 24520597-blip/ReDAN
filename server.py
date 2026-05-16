"""
server.py — Victim Server
IP: 1.1.1.10  Port: 8080
Chạy: python3 server.py
"""

import socket
import threading
import time

SERVER_IP   = "1.1.1.10"
SERVER_PORT = 8080

active_connections = {}   # { (ip, port): socket }
lock = threading.Lock()

# ─────────────────────────────────────────
def handle_client(conn, addr):
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