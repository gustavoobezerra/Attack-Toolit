# language: Python 3, file: hash_identifier.py, target: Windows/Linux
# Identifies hash type by length and character set.
import re
import sys

HASH_PATTERNS = [
    (r'^[a-f0-9]{32}$', 'MD5'),
    (r'^[a-f0-9]{40}$', 'SHA1'),
    (r'^[a-f0-9]{56}$', 'SHA224'),
    (r'^[a-f0-9]{64}$', 'SHA256'),
    (r'^[a-f0-9]{96}$', 'SHA384'),
    (r'^[a-f0-9]{128}$', 'SHA512'),
    (r'^\$2[ayb]\$.{56}$', 'bcrypt'),
    (r'^\$1\$.{1,8}\$.{22}$', 'MD5-crypt'),
    (r'^\$6\$.{1,16}\$.{86}$', 'SHA512-crypt'),
    (r'^[a-f0-9]{32}:[a-f0-9]+$', 'MD5:salt'),
    (r'^sha1\$', 'Django SHA1'),
    (r'^pbkdf2_sha256\$', 'Django PBKDF2'),
    (r'^[a-zA-Z0-9+/]{43}=$', 'Base64 (likely SHA256)'),
    (r'^[0-9a-f]{8}-[0-9a-f]{4}', 'UUID (not a hash)'),
    (r'^\*[A-F0-9]{40}$', 'MySQL4.1+'),
    (r'^[a-zA-Z0-9]{13}$', 'DES-crypt'),
    (r'^[a-f0-9]{16}$', 'MySQL < 4.1 / Half-MD5'),
    (r'^[a-f0-9]{48}$', 'SHA1 * 2 or Custom'),
]

def identify(h):
    h = h.strip()
    matches = []
    for pattern, name in HASH_PATTERNS:
        if re.match(pattern, h, re.IGNORECASE):
            matches.append(name)
    return matches

def main():
    print('[*] Hash Identifier — paste hash (empty line to quit)')
    while True:
        h = input('Hash: ').strip()
        if not h:
            break
        results = identify(h)
        if results:
            print(f'  Possible: {" | ".join(results)}')
        else:
            print(f'  Unknown (len={len(h)})')

if __name__ == '__main__':
    main()
