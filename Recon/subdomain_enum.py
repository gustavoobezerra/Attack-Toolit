# language: Python 3, file: subdomain_enum.py, target: Windows/Linux
# Subdomain brute forcer using a wordlist + threaded DNS resolution.
import socket
import threading
import queue
import sys

THREADS = 100
found = []
lock = threading.Lock()

def resolve(domain):
    try:
        ip = socket.gethostbyname(domain)
        with lock:
            found.append((domain, ip))
            print(f"[FOUND] {domain} -> {ip}")
    except socket.gaierror:
        pass

def worker(q):
    while not q.empty():
        try:
            sub = q.get_nowait()
        except queue.Empty:
            return
        resolve(sub)
        q.task_done()

def main():
    target = input("Target domain (ex: example.com): ").strip()
    wordlist = input("Wordlist path: ").strip()
    try:
        with open(wordlist, 'r', errors='ignore') as f:
            subs = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] Wordlist not found.")
        sys.exit(1)
    domains = [f"{s}.{target}" for s in subs]
    print(f"[*] Testing {len(domains)} subdomains on {target}\n")
    q = queue.Queue()
    for d in domains:
        q.put(d)
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(q,), daemon=True)
        t.start()
        threads.append(t)
    q.join()
    print(f"\n[+] Found {len(found)} subdomains.")

if __name__ == "__main__":
    main()
