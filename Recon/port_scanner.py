# language: Python 3, file: port_scanner.py, target: Windows/Linux
# High-performance asynchronous TCP port scanner with banner grabbing and JSON export.

import asyncio
import socket
import argparse
import json
import random
import sys
import time
from typing import List, Dict, Any, Optional

PROBES: Dict[int, bytes] = {
    80: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    443: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    21: b"",
    22: b"",
    25: b"",
    110: b"",
    143: b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
}

async def grab_banner(host: str, port: int, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        probe = PROBES.get(port, b"")
        if probe:
            writer.write(probe)
            await writer.drain()
        
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        banner = data.decode(errors="replace").strip().split("\n")[0]
        return banner[:120]
    except Exception:
        return ""

async def scan_port(host: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            
            banner = await grab_banner(host, port, timeout)
            return {"port": port, "status": "open", "banner": banner}
        except (asyncio.TimeoutError, OSError):
            return None

async def run_scan(target: str, ports: List[int], concurrency: int, timeout: float, randomize: bool) -> List[Dict[str, Any]]:
    if randomize:
        random.shuffle(ports)
        
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [scan_port(target, p, timeout, semaphore) for p in ports]
    
    results = []
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res:
            results.append(res)
            print(f"[+] OPEN: {target}:{res['port']} | Banner: {res['banner']}")
            
    results.sort(key=lambda x: x["port"])
    return results

def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def main() -> None:
    parser = argparse.ArgumentParser(description="Async TCP Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g. 80,443 or 1-1000)")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Max concurrent tasks")
    parser.add_argument("--timeout", type=float, default=1.5, help="Socket timeout in seconds")
    parser.add_argument("--randomize", action="store_true", help="Randomize port scan order")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    
    args = parser.parse_args()
    
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror as e:
        print(f"[!] Could not resolve host {args.target}: {e}")
        sys.exit(1)
        
    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.target} ({target_ip}) across {len(ports)} ports | Concurrency: {args.concurrency}")
    
    start_time = time.time()
    open_ports = asyncio.run(run_scan(target_ip, ports, args.concurrency, args.timeout, args.randomize))
    elapsed = time.time() - start_time
    
    print(f"\n[+] Scan finished in {elapsed:.2f}s. Found {len(open_ports)} open port(s).")
    
    if args.output:
        report = {
            "target": args.target,
            "ip": target_ip,
            "scan_duration": elapsed,
            "open_ports": open_ports
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()
