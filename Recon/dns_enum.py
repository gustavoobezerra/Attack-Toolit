# language: Python 3, file: dns_enum.py, target: Windows/Linux
# DNS record enumerator — queries A, AAAA, MX, NS, TXT, CNAME, SOA records.
import socket
from dns import resolver as dns_resolver  # dnspython
import sys

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

def query(domain, rtype):
    try:
        answers = dns_resolver.resolve(domain, rtype)
        for rdata in answers:
            print(f"  [{rtype}] {rdata}")
    except Exception:
        pass

def zone_transfer(domain):
    try:
        ns_answers = dns_resolver.resolve(domain, 'NS')
        for ns in ns_answers:
            ns_str = str(ns)
            print(f"[*] Trying zone transfer from {ns_str}...")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_str, domain))
                names = z.nodes.keys()
                for n in names:
                    print(f"  [AXFR] {n}.{domain}")
                print("  [!] Zone transfer SUCCEEDED")
            except Exception:
                print(f"  [-] Failed on {ns_str}")
    except Exception:
        pass

def main():
    import dns.zone, dns.query
    domain = input("Target domain (ex: example.com): ").strip()
    print(f"\n[*] DNS enumeration for {domain}\n")
    for rtype in RECORD_TYPES:
        query(domain, rtype)
    print()
    zone_transfer(domain)
    print("\n[+] Done.")

if __name__ == "__main__":
    main()
