# language: Python 3, file: header_audit.py, target: Windows/Linux
# HTTP security header auditor — checks which protective headers are missing or misconfigured.
import requests
import sys

TIMEOUT = 10
CHECKS = {
    'Strict-Transport-Security': 'MISSING — HSTS not set',
    'Content-Security-Policy': 'MISSING — CSP not set',
    'X-Frame-Options': 'MISSING — clickjacking risk',
    'X-Content-Type-Options': 'MISSING — MIME sniff risk',
    'Referrer-Policy': 'MISSING',
    'Permissions-Policy': 'MISSING',
    'X-XSS-Protection': 'MISSING (legacy browsers)',
    'Server': None,  # presence = info leak
    'X-Powered-By': None,
}

def main():
    url = input("Target URL (ex: https://example.com): ").strip()
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
    except Exception as e:
        print(f"[ERR] {e}")
        sys.exit(1)
    headers = {k.lower(): v for k, v in r.headers.items()}
    print(f"\n[*] Headers for {url}\n")
    for header, note in CHECKS.items():
        val = headers.get(header.lower())
        if note is None:
            if val:
                print(f"[INFO LEAK] {header}: {val}")
        else:
            if not val:
                print(f"[WARN] {note}")
            else:
                print(f"[ OK ] {header}: {val}")
    print("\n[+] Done.")

if __name__ == "__main__":
    import urllib3; urllib3.disable_warnings()
    main()
