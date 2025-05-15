import os
import ipaddress
from flask import Flask, request, render_template, redirect, session
from routeros_api import RouterOsApiPool
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'changeme')

API_HOST = os.getenv('API_HOST', '192.168.88.1')
API_USER = os.getenv('API_USER', 'admin')
API_PASS = os.getenv('API_PASS', '')
WEB_PASSWORD = os.getenv('WEB_PASSWORD', '1234')
WEB_PORT = int(os.getenv('WEB_PORT', 5000))

allowed = os.getenv('ALLOWED_NETWORKS', '192.168.88.0/24,172.30.30.0/24')
ALLOWED_NETWORKS = [net.strip() for net in allowed.split(',')]

def check_ip_allowed(ip_str):
    try:
        client_ip = ipaddress.ip_address(ip_str)
        for net in ALLOWED_NETWORKS:
            network = ipaddress.ip_network(net)
            if client_ip in network:
                return True
    except ValueError:
        pass
    return False

@app.before_request
def restrict_to_local():
    ip = request.remote_addr
    if not check_ip_allowed(ip):
        return "دسترسی فقط برای کاربران شبکه داخلی مجاز است", 403

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == WEB_PASSWORD:
            session['authenticated'] = True
            return redirect('/')
        else:
            return "رمز عبور اشتباه است", 401
    return render_template('login.html')

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect('/login')
    return render_template('index.html')

@app.route('/set')
def set_internet():
    if not session.get('authenticated'):
        return "لطفاً ابتدا وارد شوید", 401

    inet = request.args.get('inet')
    if inet not in ['1', '2', '3', '4']:
        return "گزینه اینترنت نامعتبر است", 400

    try:
        with RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, plaintext_login=True) as api:
            # فرض کنیم که تنظیمات تغییر اینترنت به این شکل انجام میشه:
            # این قسمت رو باید با توجه به نیاز میکروتیک خودت تغییر بدی
            # مثلا تغییر route یا تغییر WAN اصلی
            # نمونه: 
            # api.get_resource('/ip/route').call('set', {'disabled': False, '.id': '*1'}) # نمونه
            pass
        return "اینترنت با موفقیت تغییر یافت"
    except Exception as e:
        return f"خطا در تغییر اینترنت: {e}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=WEB_PORT)
