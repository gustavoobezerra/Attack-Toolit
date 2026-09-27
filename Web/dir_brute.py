# language: Python 3, file: dir_brute.py, target: Windows/Linux
# High-speed async web directory and file brute-forcer with soft-404 detection and WAF evasion.

import asyncio
import argparse
import json
import random
import sys
import time
import hashlib
from typing import List, Dict, Any, Optional

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

class DirBruter:
    def __init__(self, target: str, wordlist_path: str, extensions: List[str], concurrency: int, timeout: float, proxy: Optional[str] = None):
        import httpx
        self.target = target.rstrip('/')
        self.wordlist_path = wordlist_path
        self.extensions = extensions
        self.concurrency = concurrency
        self.timeout = timeout
        self.proxy = proxy
        self.httpx = httpx
        self.soft_404_hashes = set()
        self.found = []

    async def get_soft_404_baseline(self, client):
        """Generates random requests to compute soft-404 response hashes."""
        for _ in range(3):
            rand_str = f"/soft404_check_{random.randint(100000, 999999)}"
            try:
                r = await client.get(self.target + rand_str, timeout=self.timeout)
                if r.status_code == 200:
                    h = hashlib.md5(r.content).hexdigest()
                    self.soft_404_hashes.add(h)
            except Exception:
                pass

    async def check_path(self, client, path: str, semaphore: asyncio.Semaphore):
        async with semaphore:
            url = f"{self.target}/{path.lstrip('/')}"
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            try:
                r = await client.get(url, headers=headers, follow_redirects=False, timeout=self.timeout)
                if r.status_code not in (404, 400):
                    # Check for soft-404 hash collision
                    if r.status_code == 200:
                        body_hash = hashlib.md5(r.content).hexdigest()
                        if body_hash in self.soft_404_hashes:
                            return
                    
                    item = {"url": url, "status": r.status_code, "length": len(r.content)}
                    self.found.append(item)
                    print(f"[+] [{r.status_code}] {url} ({len(r.content)} bytes)")
            except Exception:
                pass

    async def run(self, randomize: bool) -> List[Dict[str, Any]]:
        try:
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                base_paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {self.wordlist_path}")
            sys.exit(1)

        full_paths = []
        for p in base_paths:
            full_paths.append(p)
            for ext in self.extensions:
                clean_ext = ext if ext.startswith('.') else f".{ext}"
                full_paths.append(f"{p}{clean_ext}")

        if randomize:
            random.shuffle(full_paths)

        print(f"[*] Target   : {self.target}")
        print(f"[*] Paths    : {len(full_paths)} (with extensions)")
        print(f"[*] Tasks    : {self.concurrency}\n")

        limits = self.httpx.Limits(max_connections=self.concurrency, max_keepalive_connections=self.concurrency)
        transport_kwargs = {"verify": False}
        if self.proxy:
            transport_kwargs["proxy"] = self.proxy

        async with self.httpx.AsyncClient(limits=limits, **transport_kwargs) as client:
            await self.get_soft_404_baseline(client)
            if self.soft_404_hashes:
                print(f"[*] Detected soft-404 baseline ({len(self.soft_404_hashes)} hashes)")

            semaphore = asyncio.Semaphore(self.concurrency)
            tasks = [self.check_path(client, p, semaphore) for p in full_paths]
            await asyncio.gather(*tasks)

        return self.found

def main():
    parser = argparse.ArgumentParser(description="Async Web Directory Brute-Forcer")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g. http://example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist path")
    parser.add_argument("-x", "--extensions", default="", help="Comma-separated extensions (e.g. php,html,bak)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Concurrent HTTP workers")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout")
    parser.add_argument("--proxy", help="HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--randomize", action="store_true", help="Randomize wordlist order")
    parser.add_argument("-o", "--output", help="Output JSON file path")

    args = parser.parse_args()

    try:
        import httpx
    except ImportError:
        print("[!] Missing required library 'httpx'. Install via: pip install httpx")
        sys.exit(1)

    exts = [e.strip() for e in args.extensions.split(',') if e.strip()] if args.extensions else []
    bruter = DirBruter(args.target, args.wordlist, exts, args.concurrency, args.timeout, args.proxy)
    
    start_time = time.time()
    results = asyncio.run(bruter.run(args.randomize))
    elapsed = time.time() - start_time

    print(f"\n[+] Brute-force completed in {elapsed:.2f}s. Found {len(results)} paths.")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({"target": args.target, "duration": elapsed, "found": results}, f, indent=2)
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    main()
