# language: Python 3, file: hashcat_wrapper.py, target: Windows/Linux
# Hashcat wrapper with menu for common attack modes.
# Requires hashcat installed and on PATH.
import subprocess
import sys

MODES = {
    '0':   ('MD5',              '0'),
    '100': ('SHA1',             '100'),
    '1400':('SHA256',           '1400'),
    '1800':('SHA512-crypt',     '1800'),
    '3200':('bcrypt',           '3200'),
    '1000':('NTLM',             '1000'),
    '2500':('WPA/WPA2-PMKID',   '2500'),
    '22000':('WPA-PBKDF2-PMKID','22000'),
    '5500':('NetNTLMv1',        '5500'),
    '5600':('NetNTLMv2',        '5600'),
}

def main():
    print('[*] Hashcat Wrapper\n')
    print('Hash modes:')
    for k, (name, _) in MODES.items():
        print(f'  {k:6} -> {name}')
    mode = input('\nMode (ex: 0 for MD5): ').strip()
    hashfile = input('Hash file path: ').strip()
    wordlist = input('Wordlist path: ').strip()
    rules = input('Rules file (blank = none): ').strip()
    outfile = input('Output file (blank = cracked.txt): ').strip() or 'cracked.txt'

    cmd = [
        'hashcat', '-m', mode,
        '-a', '0',
        hashfile, wordlist,
        '--outfile', outfile,
        '--status', '--status-timer=5'
    ]
    if rules:
        cmd += ['-r', rules]

    print(f'\n[>] {" ".join(cmd)}\n')
    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        print('[!] hashcat not found. Install it: https://hashcat.net')

if __name__ == '__main__':
    main()
