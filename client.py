"""
client.py — Victim Client
IP: 192.168.1.10
Chạy: python3 client.py
"""

import socket
import threading
import time

SERVER_IP    = "1.1.1.10"
SERVER_PORT  = 8080
NUM_CONNS    = 2          # S1, S2 như trong diagram
HEARTBEAT_S  = 5          # gửi heartbeat mỗi 5 giây
RECONNECT_S  = 3          # thử kết nối lại sau 3 giây

# ─────────────────────────────────────────
def connection_worker(conn_id: int):
    """
    Mỗi worker duy trì 1 kết nối TCP liên tục đến server.
    Khi kết nối bị ngắt → tự động reconnect (để test Stage 3).
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            local_port = s.getsockname()[1]
            print(f"[+] S{conn_id} connected  local_port={local_port}  attempt={attempt}")
            attempt = 0  # reset sau khi kết nối thành công

            while True:
                msg = f"HEARTBEAT-S{conn_id}".encode()
                s.sendall(msg)
                time.sleep(HEARTBEAT_S)

        except ConnectionRefusedError:
            print(f"[-] S{conn_id} refused    (server socket torn down?)")
        except ConnectionResetError:
            print(f"[-] S{conn_id} RST        (TCP reset by attacker)")
        except BrokenPipeError:
            print(f"[-] S{conn_id} broken     (connection lost)")
        except Exception as e:
            print(f"[-] S{conn_id} error      {e}")
        finally:
            try:
                s.close()
            except Exception:
                pass

        print(f"[~] S{conn_id} reconnecting in {RECONNECT_S}s...")
        time.sleep(RECONNECT_S)


# ─────────────────────────────────────────
if __name__ == "__main__":
    print(f"[*] Victim Client starting {NUM_CONNS} connections to {SERVER_IP}:{SERVER_PORT}\n")

    threads = []
    for i in range(1, NUM_CONNS + 1):
        t = threading.Thread(target=connection_worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.5)     # stagger để NAT map sang x_s khác nhau

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Client exiting.")