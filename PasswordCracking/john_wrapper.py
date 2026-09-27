# language: Python 3, file: john_wrapper.py, target: Windows/Linux
# John the Ripper wrapper with common formats and modes.
# Requires john installed and on PATH.
import subprocess
import sys

FORMATS = [
    'md5crypt', 'bcrypt', 'sha512crypt', 'sha256crypt',
    'nt', 'lm', 'raw-md5', 'raw-sha1', 'raw-sha256',
    'raw-sha512', 'mysql-sha1', 'zip', 'pdf', 'office',
    'ssh', 'vnc', 'wpapsk',
]

def main():
    print('[*] John the Ripper Wrapper\n')
    print('Common formats:', ', '.join(FORMATS))
    hashfile = input('\nHash file path: ').strip()
    fmt = input('Format (blank = auto-detect): ').strip()
    wordlist = input('Wordlist path (blank = incremental mode): ').strip()
    rules = input('Rules (blank = none, ex: best64): ').strip()
    show = input('Show cracked only? (y/N): ').strip().lower() == 'y'

    if show:
        cmd = ['john', '--show', hashfile]
        if fmt:
            cmd += [f'--format={fmt}']
        subprocess.run(cmd)
        return

    cmd = ['john', hashfile]
    if fmt:
        cmd += [f'--format={fmt}']
    if wordlist:
        cmd += [f'--wordlist={wordlist}']
    else:
        cmd += ['--incremental']
    if rules:
        cmd += [f'--rules={rules}']

    print(f'\n[>] {" ".join(cmd)}\n')
    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        print('[!] john not found. Install: apt install john')

if __name__ == '__main__':
    main()
