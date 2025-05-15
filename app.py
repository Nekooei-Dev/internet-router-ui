from flask import Flask, request, send_file, redirect, url_for, session
from routeros_api import RouterOsApiPool
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secretkey')  # برای session

# MikroTik Router API info
API_HOST = os.getenv('API_HOST', '192.168.88.1')
API_USER = os.getenv('API_USER', 'admin')
API_PASS = os.getenv('API_PASS', '')

# صفحه ورود
WEB_PASSWORD = os.getenv('WEB_PASSWORD', '1234')

# محدود کردن دسترسی به شبکه داخلی
ALLOWED_NETWORK = '192.168.88.'

@app.before_request
def limit_to_internal():
    ip = request.remote_addr
    if not ip.startswith(ALLOWED_NETWORK):
        return "دسترسی فقط برای کاربران داخل شبکه مجاز است", 403

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == WEB_PASSWORD:
            session['authenticated'] = True
            return redirect('/')
        else:
            return "رمز اشتباه است"
    return '''
        <form method="POST">
            <input type="password" name="password" placeholder="رمز عبور">
            <input type="submit" value="ورود">
        </form>
    '''

@app.route('/')
def home():
    if not session.get('authenticated'):
        return redirect('/login')
    return send_file("index.html")

@app.route('/set')
def set_internet():
    if not session.get('authenticated'):
        return redirect('/login')

    ip = request.remote_addr
    inet = request.args.get("inet")

    try:
        api_pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS)
        api = api_pool.get_api()

        mangle = api.get_resource('/ip/firewall/mangle')

        # حذف rule قدیمی
        old = mangle.get(src_address=ip, comment='user-routing')
        for rule in old:
            mangle.remove(id=rule['.id'])

        # افزودن rule جدید
        mangle.add(
            chain='prerouting',
            src_address=ip,
            action='mark-routing',
            new_routing_mark=f'to_internet{inet}',
            passthrough='yes',
            comment='user-routing'
        )

        api_pool.disconnect()
        return 'OK'

    except Exception as e:
        return f'خطا: {e}"
