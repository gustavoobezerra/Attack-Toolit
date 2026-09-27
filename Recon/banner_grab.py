# language: Python 3, file: banner_grab.py, target: Windows/Linux
# Banner grabber — connects to host:port list and reads the initial server response.
import socket
import sys

TIMEOUT = 3
PROBES = {
    21: b'',
    22: b'',
    23: b'',
    25: b'',
    80: b'HEAD / HTTP/1.0\r\n\r\n',
    110: b'',
    143: b'',
    443: b'HEAD / HTTP/1.0\r\n\r\n',
    3306: b'',
    5432: b'',
    6379: b'PING\r\n',
    8080: b'HEAD / HTTP/1.0\r\n\r\n',
}

def grab(host, port):
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        probe = PROBES.get(port, b'')
        if probe:
            s.send(probe)
        banner = s.recv(1024).decode(errors='replace').strip()
        s.close()
        return banner
    except Exception:
        return None

def main():
    host = input("Target host/IP: ").strip()
    ports_str = input("Ports (ex: 21,22,80,443 or press Enter for common): ").strip()
    if ports_str:
        ports = [int(p.strip()) for p in ports_str.split(',')]
    else:
        ports = list(PROBES.keys())
    print(f"\n[*] Grabbing banners from {host}\n")
    for port in ports:
        banner = grab(host, port)
        if banner:
            first_line = banner.split('\n')[0][:120]
            print(f"  [{port}] {first_line}")
        else:
            print(f"  [{port}] closed / no banner")
    print("\n[+] Done.")

if __name__ == "__main__":
    main()
