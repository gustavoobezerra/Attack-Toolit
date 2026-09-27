# language: Python 3, file: port_scanner.py, target: Windows/Linux
# Fast threaded TCP port scanner with banner grabbing on open ports.
import socket
import threading
import queue
import sys

THREADS = 200
TIMEOUT = 1.0
open_ports = []
lock = threading.Lock()

def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((host, port)) == 0:
            banner = ''
            try:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = s.recv(256).decode(errors='replace').split('\n')[0].strip()
            except Exception:
                pass
            with lock:
                open_ports.append(port)
                print(f"[OPEN] {host}:{port}  {banner}")
        s.close()
    except Exception:
        pass

def worker(q, host):
    while not q.empty():
        try:
            port = q.get_nowait()
        except queue.Empty:
            return
        scan_port(host, port)
        q.task_done()

def main():
    host = input("Target host/IP: ").strip()
    range_str = input("Port range (ex: 1-65535 or 1-1000): ").strip()
    start, end = (int(x) for x in range_str.split('-'))
    print(f"[*] Scanning {host} ports {start}-{end} | {THREADS} threads\n")
    q = queue.Queue()
    for p in range(start, end + 1):
        q.put(p)
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(q, host), daemon=True)
        t.start()
        threads.append(t)
    q.join()
    print(f"\n[+] {len(open_ports)} open port(s): {sorted(open_ports)}")

if __name__ == "__main__":
    main()
