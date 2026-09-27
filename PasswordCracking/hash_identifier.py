#!/usr/bin/env python3
# =============================================================================
# Filename: hash_identifier.py
# Description: Advanced hash identifier supporting 20+ hash types. Detects
#              hash type, reports hashcat mode, length, charset confidence.
# Author: PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import json
import re
import sys

from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------------------------------------------------
# Hash definitions: (name, regex, hashcat_mode, confidence_note)
# ---------------------------------------------------------------------------
HASH_SIGNATURES = [
    # Ordered from most specific to least specific
    {
        "name": "bcrypt",
        "pattern": re.compile(r"^\$2[aby]\$\d{2}\$.{53}$"),
        "hashcat_mode": 3200,
        "charset": "special",
    },
    {
        "name": "scrypt",
        "pattern": re.compile(r"^\$scrypt\$"),
        "hashcat_mode": 8900,
        "charset": "special",
    },
    {
        "name": "Argon2i",
        "pattern": re.compile(r"^\$argon2i\$"),
        "hashcat_mode": 13400,
        "charset": "special",
    },
    {
        "name": "Argon2id",
        "pattern": re.compile(r"^\$argon2id\$"),
        "hashcat_mode": 13400,
        "charset": "special",
    },
    {
        "name": "PBKDF2-SHA256 (Django)",
        "pattern": re.compile(r"^pbkdf2_sha256\$"),
        "hashcat_mode": 10000,
        "charset": "special",
    },
    {
        "name": "WordPress ($P$)",
        "pattern": re.compile(r"^\$P\$[./0-9A-Za-z]{31}$"),
        "hashcat_mode": 400,
        "charset": "special",
    },
    {
        "name": "md5crypt ($1$)",
        "pattern": re.compile(r"^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$"),
        "hashcat_mode": 500,
        "charset": "special",
    },
    {
        "name": "sha256crypt ($5$)",
        "pattern": re.compile(r"^\$5\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$"),
        "hashcat_mode": 7400,
        "charset": "special",
    },
    {
        "name": "sha512crypt ($6$)",
        "pattern": re.compile(r"^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$"),
        "hashcat_mode": 1800,
        "charset": "special",
    },
    {
        "name": "MySQL 4.1+ (*hash)",
        "pattern": re.compile(r"^\*[0-9A-Fa-f]{40}$"),
        "hashcat_mode": 300,
        "charset": "hex",
    },
    {
        "name": "LM",
        "pattern": re.compile(r"^[0-9A-Fa-f]{32}$"),  # same as MD5 length but usually paired
        "hashcat_mode": 3000,
        "charset": "hex",
    },
    {
        "name": "NTLM",
        "pattern": re.compile(r"^[0-9A-Fa-f]{32}$"),
        "hashcat_mode": 1000,
        "charset": "hex",
    },
    {
        "name": "MD5",
        "pattern": re.compile(r"^[0-9A-Fa-f]{32}$"),
        "hashcat_mode": 0,
        "charset": "hex",
    },
    {
        "name": "MySQL OLD (< 4.1)",
        "pattern": re.compile(r"^[0-9A-Fa-f]{16}$"),
        "hashcat_mode": 200,
        "charset": "hex",
    },
    {
        "name": "SHA1",
        "pattern": re.compile(r"^[0-9A-Fa-f]{40}$"),
        "hashcat_mode": 100,
        "charset": "hex",
    },
    {
        "name": "SHA224",
        "pattern": re.compile(r"^[0-9A-Fa-f]{56}$"),
        "hashcat_mode": 1300,
        "charset": "hex",
    },
    {
        "name": "SHA256",
        "pattern": re.compile(r"^[0-9A-Fa-f]{64}$"),
        "hashcat_mode": 1400,
        "charset": "hex",
    },
    {
        "name": "SHA384",
        "pattern": re.compile(r"^[0-9A-Fa-f]{96}$"),
        "hashcat_mode": 10800,
        "charset": "hex",
    },
    {
        "name": "SHA512",
        "pattern": re.compile(r"^[0-9A-Fa-f]{128}$"),
        "hashcat_mode": 1700,
        "charset": "hex",
    },
    {
        "name": "SHA3-256",
        "pattern": re.compile(r"^[0-9A-Fa-f]{64}$"),
        "hashcat_mode": 17300,
        "charset": "hex",
    },
    {
        "name": "SHA3-512",
        "pattern": re.compile(r"^[0-9A-Fa-f]{128}$"),
        "hashcat_mode": 17600,
        "charset": "hex",
    },
]

LENGTH_PRIORITY = {
    16: ["MySQL OLD (< 4.1)"],
    32: ["MD5", "NTLM", "LM"],
    40: ["SHA1"],
    56: ["SHA224"],
    64: ["SHA256", "SHA3-256"],
    96: ["SHA384"],
    128: ["SHA512", "SHA3-512"],
    41: ["MySQL 4.1+ (*hash)"],
}


def detect_charset(h):
    if re.match(r"^[0-9A-Fa-f]+$", h):
        return "hex"
    if re.match(r"^[A-Za-z0-9+/=]+$", h):
        return "base64"
    return "special"


def identify_hash(h):
    results = []
    seen = set()
    for sig in HASH_SIGNATURES:
        if sig["pattern"].match(h):
            name = sig["name"]
            if name not in seen:
                seen.add(name)
                # confidence: high for special patterns, medium for hex length matches
                confidence = "HIGH" if sig["charset"] == "special" else "MEDIUM"
                results.append({
                    "name": name,
                    "hashcat_mode": sig["hashcat_mode"],
                    "confidence": confidence,
                })
    return results


def analyze_hash(h):
    length = len(h)
    charset = detect_charset(h)
    types = identify_hash(h)
    return {
        "hash": h,
        "length": length,
        "charset": charset,
        "identified_types": types,
    }


def print_result(result):
    h = result["hash"]
    length = result["length"]
    charset = result["charset"]
    types = result["identified_types"]

    print(f"\n{Fore.CYAN}Hash   : {h}{Style.RESET_ALL}")
    print(f"Length : {length}  |  Charset: {charset}")

    if not types:
        print(f"{Fore.RED}[!] No matching hash type found.{Style.RESET_ALL}")
        return

    print(f"Possible types ({len(types)}):")
    for t in types:
        conf_color = Fore.GREEN if t["confidence"] == "HIGH" else Fore.YELLOW
        print(
            f"  {Fore.CYAN}{t['name']:<35}{Style.RESET_ALL}"
            f"  Hashcat: {Fore.YELLOW}{t['hashcat_mode']:<6}{Style.RESET_ALL}"
            f"  Confidence: {conf_color}{t['confidence']}{Style.RESET_ALL}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="PARALELEPIPEDO - Hash Identifier",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--hash", help="Single hash to identify")
    group.add_argument("--file", help="File containing hashes (one per line)")
    parser.add_argument("--output-json", help="Save results as JSON to this file")
    args = parser.parse_args()

    print(f"{Fore.CYAN}[*] PARALELEPIPEDO Hash Identifier{Style.RESET_ALL}")

    hashes = []
    if args.hash:
        hashes = [args.hash.strip()]
    elif args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                hashes = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[!] File not found: {args.file}{Style.RESET_ALL}")
            sys.exit(1)

    all_results = []
    for h in hashes:
        result = analyze_hash(h)
        print_result(result)
        all_results.append(result)

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)
        print(f"\n{Fore.GREEN}[+] JSON results saved to {args.output_json}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
