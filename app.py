from flask import Flask, request, send_file, redirect, url_for, session
from routeros_api import RouterOsApiPool
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'changeme')

API_HOST = os.getenv('API_HOST', '192.168.88.1')
API_USER = os.getenv('API_USER', 'admin')
API_PASS = os.getenv('API_PASS', '')
WEB_PASSWORD = os.getenv('WEB_PASSWORD', '1234')

ALLOWED_NETWORK = '192.168.88.'

@app.before_request
def restrict_to_local():
    ip = request.remote_addr
    if not ip.startswith(ALLOWED_NETWORK):
        return "دسترسی فقط برای کاربران شبکه داخلی مجاز است", 403

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == WEB_PASSWORD:
            session['authenticated'] = True
            return redirect('/')
        else:
            return "رمز عبور اشتباه است"
    return '''
        <
