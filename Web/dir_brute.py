# language: Python 3, file: dir_brute.py, target: Windows/Linux
# Directory/file brute forcer — threads GET requests with a wordlist against target.
import threading
import requests
import queue
import sys

THREADS = 50
TIMEOUT = 5
FOUND = []

def worker(q, base_url, session):
    while not q.empty():
        try:
            path = q.get_nowait()
        except queue.Empty:
            return
        url = base_url.rstrip('/') + '/' + path.strip()
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            code = r.status_code
            if code not in (404, 400):
                print(f"[{code}] {url}")
                FOUND.append(url)
        except Exception:
            pass
        finally:
            q.task_done()

def main():
    target = input("Target URL (ex: http://example.com): ").strip()
    wordlist = input("Wordlist path (ex: /usr/share/wordlists/dirb/common.txt): ").strip()
    if not target.startswith('http'):
        target = 'http://' + target
    try:
        with open(wordlist, 'r', errors='ignore') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print("[!] Wordlist not found.")
        sys.exit(1)
    print(f"[*] Target   : {target}")
    print(f"[*] Paths    : {len(paths)}")
    print(f"[*] Threads  : {THREADS}\n")
    q = queue.Queue()
    for p in paths:
        q.put(p)
    session = requests.Session()
    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(q, target, session), daemon=True)
        t.start()
        threads.append(t)
    q.join()
    print(f"\n[+] Found {len(FOUND)} paths.")

if __name__ == "__main__":
    main()
