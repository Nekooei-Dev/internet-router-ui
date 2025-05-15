from flask import Flask, request, redirect, session, render_template
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
WEB_PORT = int(os.getenv('WEB_PORT', 5000))

# رنج های مجاز شبکه رو از ENV می‌خونیم، چندتا رنج با کاما جدا
ALLOWED_NETWORKS = os.getenv('ALLOWED_NETWORKS', '192.168.88.').split(',')

@app.before_request
def restrict_to_local():
    ip = request.remote_addr
    if not any(ip.startswith(net.strip()) for net in ALLOWED_NETWORKS):
        return "دسترسی فقط برای کاربران شبکه داخلی مجاز است", 403

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == WEB_PASSWORD:
            session['authenticated'] = True
            return redirect('/')
        else:
            return "رمز عبور اشتباه است"
    return render_template('login.html')

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect('/login')
    return render_template('index.html')

@app.route('/set')
def set_internet():
    if not session.get('authenticated'):
        return "لطفا وارد شوید", 401

    inet = request.args.get('inet')
    if inet not in ['1', '2', '3', '4']:
        return "پارامتر نامعتبر", 400

    try:
        api = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, plaintext_login=True)
        api_instance = api.get_api()
        # اینجا دستور تغییر اینترنت رو به میکروتیک می‌فرستی
        # فرضا می‌خوای route یا default gateway رو تغییر بدی
        # این مثال فقط یک placeholder هست:
        api_instance.get_resource('/ip/route').call('set', {'gateway': f'pppoe-out{inet}'})
        api.disconnect()
        return "اینترنت با موفقیت تغییر یافت"
    except Exception as e:
        return f"خطا در تغییر اینترنت: {e}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=WEB_PORT)
