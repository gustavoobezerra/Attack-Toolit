
# =============================================================================
# Filename   : port_knock.py
# Description: Port knocking client and server.
#              Client sends a crafted packet sequence; server sniffs for the
#              sequence per-IP and executes a command on success.
#              Part of PARALELEPIPEDO Toolkit.
# Author     : PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import subprocess
import sys
import time
import threading
from collections import defaultdict

from colorama import Fore, Style, init
from scapy.all import (
    IP, TCP, UDP,
    RandShort,
    send, sniff, conf
)

init(autoreset=True)


def info(msg):  print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):  print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):   print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def knock_msg(msg): print(f"{Fore.CYAN}[KNOCK]{Style.RESET_ALL} {msg}")
def success(msg):   print(f"{Fore.MAGENTA}[SUCCESS]{Style.RESET_ALL} {msg}")


# ===========================================================================
# CLIENT
# ===========================================================================

def client_mode(host: str, sequence: list[int], protocol: str,
                delay_ms: float, open_port: int | None):
    """Send crafted TCP SYN or UDP packets to each port in sequence."""
    delay_s = delay_ms / 1000.0

    info(f"Knocking {host} sequence: {sequence}  protocol: {protocol.upper()}")

    for idx, port in enumerate(sequence, 1):
        if protocol == "tcp":
            pkt = IP(dst=host) / TCP(dport=port, sport=int(RandShort()), flags="S")
        else:
            pkt = IP(dst=host) / UDP(dport=port, sport=int(RandShort()))

        send(pkt, verbose=False)
        knock_msg(f"[{idx}/{len(sequence)}] Sent {protocol.upper()} to port {port}")
        if idx < len(sequence):
            time.sleep(delay_s)

    info("Knock sequence complete.")

    if open_port:
        import socket
        info(f"Attempting connection to {host}:{open_port} ...")
        try:
            with socket.create_connection((host, open_port), timeout=5) as s:
                success(f"Connected to {host}:{open_port}")
        except (ConnectionRefusedError, OSError) as exc:
            warn(f"Connection to {host}:{open_port} failed: {exc}")


# ===========================================================================
# SERVER
# ===========================================================================

class KnockServer:
    def __init__(self, sequence: list[int], timeout: float,
                 action: str | None, iface: str):
        self.sequence = sequence
        self.timeout  = timeout
        self.action   = action
        self.iface    = iface

        # Per-IP knock state: {ip: {"idx": int, "ts": float}}
        self._state: dict[str, dict] = defaultdict(lambda: {"idx": 0, "ts": 0.0})
        self._lock  = threading.Lock()

    def _expire_old(self, now: float):
        for ip, st in list(self._state.items()):
            if st["idx"] > 0 and (now - st["ts"]) > self.timeout:
                warn(f"{ip} knock sequence timed out, resetting.")
                self._state[ip] = {"idx": 0, "ts": 0.0}

    def _on_unlock(self, src_ip: str):
        success(f"Knock sequence complete from {src_ip}!")
        if self.action:
            info(f"Running action: {self.action}")
            try:
                result = subprocess.run(
                    self.action, shell=True, capture_output=True, text=True
                )
                info(f"Action stdout: {result.stdout.strip()}")
                if result.stderr:
                    warn(f"Action stderr: {result.stderr.strip()}")
            except Exception as exc:
                err(f"Action failed: {exc}")
        else:
            info("No action configured. Unlock acknowledged.")

    def handle(self, pkt):
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        now    = time.time()

        # Determine the knocked port
        dst_port = None
        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport

        if dst_port is None:
            return

        with self._lock:
            self._expire_old(now)
            st  = self._state[src_ip]
            idx = st["idx"]

            if dst_port == self.sequence[idx]:
                st["idx"] = idx + 1
                st["ts"]  = now
                knock_msg(
                    f"{src_ip}  port {dst_port}  "
                    f"[{st['idx']}/{len(self.sequence)}]"
                )
                if st["idx"] == len(self.sequence):
                    self._state[src_ip] = {"idx": 0, "ts": 0.0}
                    # Run in a thread so sniff loop is not blocked
                    threading.Thread(
                        target=self._on_unlock, args=(src_ip,), daemon=True
                    ).start()
            else:
                if idx > 0:
                    # Wrong port – reset
                    warn(f"{src_ip} wrong port {dst_port} (expected {self.sequence[idx]}), resetting.")
                    self._state[src_ip] = {"idx": 0, "ts": 0.0}

    def run(self):
        ports_str = ",".join(map(str, self.sequence))
        info(f"Server listening on {self.iface} for sequence: {ports_str}")
        info(f"Timeout per sequence: {self.timeout}s")
        info("Press Ctrl+C to stop.\n")

        port_filter = " or ".join(f"port {p}" for p in self.sequence)
        bpf = f"(tcp or udp) and ({port_filter})"

        try:
            sniff(
                iface=self.iface,
                filter=bpf,
                prn=self.handle,
                store=False,
            )
        except KeyboardInterrupt:
            info("Server stopped.")


# ===========================================================================
# CLI
# ===========================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="PARALELEPIPEDO Toolkit – Port Knocking Client / Server"
    )
    p.add_argument("--mode", choices=["client", "server"], required=True,
                   help="client or server")

    # Shared
    p.add_argument("--sequence",
                   help="Comma-separated port sequence (e.g. 7000,8000,9000)")
    p.add_argument("--interface", "-i", default=conf.iface,
                   help="Network interface (server / client raw send)")

    # Client-only
    p.add_argument("--host",      help="Target host (client mode)")
    p.add_argument("--protocol",  choices=["tcp", "udp"], default="tcp",
                   help="Knock protocol: tcp|udp (default: tcp)")
    p.add_argument("--delay",     type=float, default=200,
                   help="Delay in ms between knocks (default: 200)")
    p.add_argument("--open-port", type=int,
                   help="Port to connect to after successful knock (client)")

    # Server-only
    p.add_argument("--timeout",   type=float, default=10,
                   help="Seconds to complete sequence (server, default: 10)")
    p.add_argument("--action",
                   help="Shell command to run on successful knock (server)")

    return p.parse_args()


def main():
    args = parse_args()

    if not args.sequence:
        err("--sequence is required.")
        sys.exit(1)

    try:
        sequence = [int(p.strip()) for p in args.sequence.split(",")]
    except ValueError:
        err("--sequence must be comma-separated integers.")
        sys.exit(1)

    if args.mode == "client":
        if not args.host:
            err("--host is required in client mode.")
            sys.exit(1)
        client_mode(
            host=args.host,
            sequence=sequence,
            protocol=args.protocol,
            delay_ms=args.delay,
            open_port=args.open_port,
        )
    else:  # server
        server = KnockServer(
            sequence=sequence,
            timeout=args.timeout,
            action=args.action,
            iface=args.interface,
        )
        server.run()


if __name__ == "__main__":
    main()
