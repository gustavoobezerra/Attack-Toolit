# language: Python 3, file: whois_lookup.py, target: Windows/Linux
# WHOIS + basic OSINT collector for a domain or IP.
import socket
import sys

WHOIS_PORT = 43

def raw_whois(query, server='whois.iana.org'):
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect((server, WHOIS_PORT))
        s.send((query + '\r\n').encode())
        resp = b''
        while True:
            data = s.recv(4096)
            if not data:
                break
            resp += data
        s.close()
        return resp.decode(errors='replace')
    except Exception as e:
        return f'Error: {e}'

def find_whois_server(domain):
    iana = raw_whois(domain)
    for line in iana.splitlines():
        if line.lower().startswith('whois:'):
            return line.split(':', 1)[1].strip()
    return 'whois.iana.org'

def main():
    target = input("Domain or IP: ").strip()
    print(f"\n[*] WHOIS for {target}\n")
    server = find_whois_server(target)
    print(f"[*] Using WHOIS server: {server}\n")
    result = raw_whois(target, server)
    print(result)
    print('[+] Done.')

if __name__ == "__main__":
    main()
