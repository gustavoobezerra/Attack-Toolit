
# =============================================================================
# Filename   : net_scanner.py
# Description: Complete network scanner. ARP scan (layer 2), ICMP ping scan,
#              reverse DNS, optional port scan. CIDR input, JSON output.
#              Part of PARALELEPIPEDO Toolkit.
# Author     : PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import ipaddress
import json
import socket
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict

from colorama import Fore, Style, init
from scapy.all import ARP, Ether, IP, ICMP, srp, sr1, conf

init(autoreset=True)


def info(msg):  print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):  print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):   print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Host:
    ip:         str
    mac:        str = ""
    hostname:   str = ""
    open_ports: list[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ARP scan
# ---------------------------------------------------------------------------

def arp_scan(cidr: str, iface: str, timeout: float) -> list[Host]:
    """Send ARP who-has to every host in the CIDR and collect replies."""
    info(f"ARP scan on {cidr} ...")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(pkt, timeout=timeout, iface=iface, verbose=False)
    hosts = []
    for _, reply in answered:
        hosts.append(Host(ip=reply.psrc, mac=reply.hwsrc))
    return hosts


# ---------------------------------------------------------------------------
# ICMP scan
# ---------------------------------------------------------------------------

def icmp_ping(ip: str, timeout: float) -> bool:
    """Return True if host responds to ICMP echo."""
    pkt  = IP(dst=ip) / ICMP()
    resp = sr1(pkt, timeout=timeout, verbose=False)
    return resp is not None


def icmp_scan(targets: list[str], timeout: float, workers: int = 50) -> list[Host]:
    """Ping scan a list of IPs concurrently."""
    info(f"ICMP ping scan on {len(targets)} addresses ...")
    hosts = []
    lock  = threading.Lock()
    done  = [0]

    def _ping(ip):
        alive = icmp_ping(ip, timeout)
        with lock:
            done[0] += 1
            pct = done[0] * 100 // len(targets)
            print(
                f"\r{Fore.CYAN}[ICMP]{Style.RESET_ALL} "
                f"Progress: {done[0]}/{len(targets)} ({pct}%)   ",
                end="", flush=True,
            )
        return ip if alive else None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_ping, ip): ip for ip in targets}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                hosts.append(Host(ip=result))
    print()
    return hosts


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


# ---------------------------------------------------------------------------
# Port scan
# ---------------------------------------------------------------------------

def scan_port(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, OSError):
        return False


def port_scan(host: Host, ports: list[int], timeout: float, workers: int = 100):
    """Scan given ports on host and populate host.open_ports."""
    open_ports = []
    lock = threading.Lock()

    def _check(port):
        if scan_port(host.ip, port, timeout):
            with lock:
                open_ports.append(port)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_check, ports))

    host.open_ports = sorted(open_ports)


# ---------------------------------------------------------------------------
# Port list parser
# ---------------------------------------------------------------------------

def parse_ports(port_str: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' into a list of ints."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return ports


# ---------------------------------------------------------------------------
# CIDR expansion
# ---------------------------------------------------------------------------

def expand_cidr(target: str) -> list[str]:
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in net.hosts()]
    except ValueError:
        return [target]


# ---------------------------------------------------------------------------
# Table printer
# ---------------------------------------------------------------------------

def print_table(hosts: list[Host]):
    if not hosts:
        warn("No hosts found.")
        return

    h1 = "IP Address"
    h2 = "MAC"
    h3 = "Hostname"
    h4 = "Open Ports"

    col1 = max(len(h1), max(len(h.ip)       for h in hosts)) + 2
    col2 = max(len(h2), max(len(h.mac)      for h in hosts)) + 2
    col3 = max(len(h3), max(len(h.hostname) for h in hosts)) + 2

    sep = f"+{'-'*col1}+{'-'*col2}+{'-'*col3}+{'-'*30}+"

    def row(c1, c2, c3, c4, color=""):
        return (
            f"{color}|{c1:<{col1}}|{c2:<{col2}}|{c3:<{col3}}|{c4:<30}|{Style.RESET_ALL}"
        )

    print(sep)
    print(row(f" {h1}", f" {h2}", f" {h3}", f" {h4}", Fore.CYAN))
    print(sep)
    for h in hosts:
        ports_str = ", ".join(map(str, h.open_ports)) if h.open_ports else ""
        color = Fore.GREEN if h.mac else Fore.WHITE
        print(row(f" {h.ip}", f" {h.mac}", f" {h.hostname}", f" {ports_str}", color))
    print(sep)
    info(f"Total hosts discovered: {len(hosts)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="PARALELEPIPEDO Toolkit – Network Scanner"
    )
    p.add_argument("--target", required=True,
                   help="CIDR range or single IP (e.g. 192.168.1.0/24)")
    p.add_argument("--method", choices=["arp", "icmp", "both"], default="both",
                   help="Scan method: arp|icmp|both (default: both)")
    p.add_argument("--ports",
                   help="Ports to scan on discovered hosts (e.g. 22,80,443 or 1-1024)")
    p.add_argument("--timeout", type=float, default=2.0,
                   help="Timeout per probe in seconds (default: 2)")
    p.add_argument("--interface", "-i", default=conf.iface,
                   help="Network interface for ARP scan")
    p.add_argument("--output-json", metavar="FILE",
                   help="Save results as JSON to this file")
    return p.parse_args()


def main():
    args = parse_args()

    targets = expand_cidr(args.target)

    discovered: list[Host] = []
    seen_ips: set[str] = set()

    # -- ARP scan (layer 2, fast, LAN)
    if args.method in ("arp", "both"):
        arp_hosts = arp_scan(args.target, args.interface, args.timeout)
        for h in arp_hosts:
            if h.ip not in seen_ips:
                discovered.append(h)
                seen_ips.add(h.ip)
        info(f"ARP found {len(arp_hosts)} host(s).")

    # -- ICMP scan
    if args.method in ("icmp", "both"):
        icmp_targets = [ip for ip in targets if ip not in seen_ips]
        if icmp_targets:
            icmp_hosts = icmp_scan(icmp_targets, args.timeout)
            for h in icmp_hosts:
                if h.ip not in seen_ips:
                    discovered.append(h)
                    seen_ips.add(h.ip)
            info(f"ICMP found {len(icmp_hosts)} additional host(s).")

    if not discovered:
        warn("No hosts discovered.")
        return

    # -- Reverse DNS
    info("Resolving hostnames ...")
    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(resolve_hostname, h.ip): h for h in discovered}
        for fut, host in futs.items():
            host.hostname = fut.result()

    # -- Port scan
    if args.ports:
        ports = parse_ports(args.ports)
        info(f"Port scanning {len(discovered)} host(s) on {len(ports)} port(s) ...")
        for idx, host in enumerate(discovered, 1):
            print(
                f"\r{Fore.CYAN}[PORTS]{Style.RESET_ALL} "
                f"Scanning {host.ip} ({idx}/{len(discovered)})   ",
                end="", flush=True,
            )
            port_scan(host, ports, args.timeout)
        print()

    # -- Print table
    print()
    print_table(discovered)

    # -- JSON output
    if args.output_json:
        data = [asdict(h) for h in discovered]
        try:
            with open(args.output_json, "w") as fh:
                json.dump(data, fh, indent=2)
            info(f"Results saved to {args.output_json}")
        except OSError as exc:
            err(f"Failed to write JSON: {exc}")


if __name__ == "__main__":
    main()
