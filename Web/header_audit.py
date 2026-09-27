# language: Python 3, file: header_audit.py, target: Windows/Linux
# Async HTTP Security Header Auditor with detailed CSP parsing and JSON export.

import asyncio
import argparse
import json
import re
import sys
from typing import Dict, Any, List

CHECKS: Dict[str, str] = {
    "Strict-Transport-Security": "HSTS enforce HTTPS",
    "Content-Security-Policy": "CSP mitigation against XSS and Injection",
    "X-Frame-Options": "Clickjacking defense",
    "X-Content-Type-Options": "MIME-sniffing prevention",
    "Referrer-Policy": "Referrer leaks control",
    "Permissions-Policy": "Browser features restriction",
    "Cross-Origin-Opener-Policy": "Cross-origin isolation (COOP)",
    "Cross-Origin-Embedder-Policy": "Cross-origin resource loading (COEP)"
}

LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

class HeaderAuditor:
    def __init__(self, target_url: str, timeout: float = 10.0):
        import httpx
        self.httpx = httpx
        self.target_url = target_url if target_url.startswith("http") else f"https://{target_url}"
        self.timeout = timeout

    async def audit(self) -> Dict[str, Any]:
        report = {
            "target": self.target_url,
            "missing_headers": [],
            "present_headers": {},
            "info_leaks": {},
            "warnings": []
        }

        async with self.httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            try:
                r = await client.get(self.target_url)
            except Exception as e:
                print(f"[!] Connection failed: {e}")
                return report

            headers = {k.lower(): v for k, v in r.headers.items()}

            # Check security headers
            for header, desc in CHECKS.items():
                val = headers.get(header.lower())
                if not val:
                    report["missing_headers"].append({"header": header, "description": desc})
                    print(f"[-] MISSING: {header} ({desc})")
                else:
                    report["present_headers"][header] = val
                    print(f"[+] PRESENT: {header} = {val[:60]}...")

                    # Deep check HSTS
                    if header.lower() == "strict-transport-security":
                        if "max-age" not in val.lower():
                            report["warnings"].append("HSTS header missing 'max-age' directive.")

                    # Deep check CSP
                    if header.lower() == "content-security-policy":
                        if "unsafe-inline" in val.lower() or "*" in val:
                            report["warnings"].append("CSP contains weak directives ('unsafe-inline' or wildcard '*').")

            # Check info leaks
            for leak in LEAK_HEADERS:
                val = headers.get(leak.lower())
                if val:
                    report["info_leaks"][leak] = val
                    print(f"[!] INFO LEAK: {leak} = {val}")

        return report

def main():
    parser = argparse.ArgumentParser(description="Async HTTP Security Header Auditor")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout")
    parser.add_argument("-o", "--output", help="Save audit to JSON file")

    args = parser.parse_args()

    try:
        import httpx
    except ImportError:
        print("[!] Missing required library 'httpx'. Install via: pip install httpx")
        sys.exit(1)

    auditor = HeaderAuditor(args.url, args.timeout)
    print(f"[*] Auditing headers for {args.url}\n")
    report = asyncio.run(auditor.audit())

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Audit report saved to {args.output}")

if __name__ == "__main__":
    main()
