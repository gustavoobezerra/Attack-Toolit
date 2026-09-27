#!/usr/bin/env python3
"""
=============================================================================
  qr_phish.py — QR-code phishing payload generator
  Part of: PARALELEPIPEDO // SocialEngineering
  Author : PARALELEPIPEDO project
  Use    : Authorized red-team / security-awareness testing only
=============================================================================
  Deps: qrcode[pil], requests, colorama, Pillow
        pip install "qrcode[pil]" requests colorama Pillow
=============================================================================
"""

import argparse
import io
import os
import sys
from pathlib import Path

import requests
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

try:
    import qrcode
    from qrcode.image.styledpil import StyledPilImage
    from PIL import Image
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False


# ─── URL shortener ─────────────────────────────────────────────────────────────

def shorten_tinyurl(url: str) -> str:
    """Shorten URL using TinyURL API (no auth required)."""
    try:
        r = requests.get(
            "https://tinyurl.com/api-create.php",
            params={"url": url},
            timeout=8,
        )
        if r.status_code == 200 and r.text.startswith("http"):
            return r.text.strip()
    except Exception as e:
        print(f"{Fore.YELLOW}[!] TinyURL failed: {e}{Style.RESET_ALL}")
    return url


# ─── Terminal QR printer ───────────────────────────────────────────────────────

def print_qr_terminal(url: str):
    """Print a QR code to the terminal using ASCII blocks."""
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=1,
            border=2,
        )
        qr.add_data(url)
        qr.make(fit=True)

        matrix = qr.get_matrix()
        print()
        for row in matrix:
            line = ""
            for cell in row:
                # Use full block for dark, space for light
                line += "██" if cell else "  "
            print(line)
        print()
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Terminal QR failed: {e}{Style.RESET_ALL}")


# ─── PNG generation ────────────────────────────────────────────────────────────

def generate_png(url: str, output: str, logo: str | None = None):
    """Generate a QR code PNG, optionally embedding a logo."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

    if logo and os.path.isfile(logo):
        logo_img = Image.open(logo).convert("RGBA")
        qr_w, qr_h = img.size
        logo_max = qr_w // 4
        logo_img.thumbnail((logo_max, logo_max))
        logo_w, logo_h = logo_img.size
        pos = ((qr_w - logo_w) // 2, (qr_h - logo_h) // 2)
        img.paste(logo_img, pos, logo_img)

    img.save(output)
    size = os.path.getsize(output)
    print(f"{Fore.GREEN}[+] QR code saved: {output} ({size} bytes){Style.RESET_ALL}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="QR-code phishing payload generator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--url",      required=True,
                        help="Phishing / target URL")
    parser.add_argument("--output",   default="phish_qr.png",
                        help="Output PNG file path")
    parser.add_argument("--shorten",  action="store_true",
                        help="Shorten URL via TinyURL before encoding")
    parser.add_argument("--logo",     metavar="FILE",
                        help="Embed a logo image in the center of the QR")
    parser.add_argument("--no-print", action="store_true",
                        help="Skip terminal QR display")
    args = parser.parse_args()

    if not HAS_QRCODE:
        print(f'{Fore.RED}[!] Missing deps: pip install "qrcode[pil]" Pillow{Style.RESET_ALL}')
        sys.exit(1)

    url = args.url
    print(f"{Fore.CYAN}[*] Original URL : {url}{Style.RESET_ALL}")

    if args.shorten:
        short = shorten_tinyurl(url)
        print(f"{Fore.GREEN}[+] Shortened URL: {short}{Style.RESET_ALL}")
        url = short
    else:
        print(f"{Fore.YELLOW}[~] URL not shortened (use --shorten to enable){Style.RESET_ALL}")

    if not args.no_print:
        print_qr_terminal(url)

    generate_png(url, args.output, args.logo)
    print(f"{Fore.CYAN}[*] Encode target: {url}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
