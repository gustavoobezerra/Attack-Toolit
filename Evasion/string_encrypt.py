# language: Python 3, file: string_encrypt.py, target: Windows/Linux
# Encrypts hardcoded strings in a Python script with XOR to evade static AV string detection.
# Replaces plain strings with encrypted versions + inline decrypt at runtime.
import re
import sys
import os

def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def encrypt_string(s: str, key: bytes) -> str:
    enc = xor(s.encode(), key)
    hex_enc = enc.hex()
    key_repr = key.hex()
    # Returns inline Python expression that decrypts at runtime
    return (f'bytes(b ^ bytes.fromhex("{key_repr}")[i % {len(key)}] '
            f'for i, b in enumerate(bytes.fromhex("{hex_enc}"))).decode()')

def main():
    src_path = input('Python source file path: ').strip()
    key_str = input('XOR key hex (ex: cafebabe): ').strip()
    out_path = input('Output file path: ').strip() or 'obfuscated.py'

    key = bytes.fromhex(key_str)

    with open(src_path, 'r', errors='ignore') as f:
        source = f.read()

    # Find all double-quoted and single-quoted strings (simple approach)
    def replace_str(m):
        s = m.group(1) or m.group(2)
        if len(s) < 4:
            return m.group(0)
        return encrypt_string(s, key)

    # Replace "..." and '...' string literals (non-nested)
    out = re.sub(r'"([^"\\\n]+)"|\x27([^\x27\\\n]+)\x27', replace_str, source)

    with open(out_path, 'w') as f:
        f.write(out)

    print(f'[+] Obfuscated source -> {out_path}')

if __name__ == '__main__':
    main()
