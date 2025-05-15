import os
from flask import Flask, render_template, request, redirect, session, abort
from routeros_api import RouterOsApiPool
import ipaddress

app = Flask(__name__)

# دریافت تنظیمات از ENV با مقدار پیش‌فرض
API_HOST = os.getenv('API_HOST', '172.30.30.254')
API_USER = os.getenv('API_USER', 'API')
API_PASS = os.getenv('API_PASS', 'API')
API_PORT = int(os.getenv('API_PORT', '8728'))
API_USE_SSL = os.getenv('API_USE_SSL', 'false').lower() == 'true'  # اگه میخوای ssl بزنی true بذار

WEB_PASSWORD = os.getenv('WEB_PASSWORD', '123456')
WEB_PORT = int(os.getenv('WEB_PORT', '5000'))
SECRET_KEY = os.getenv('SECRET_KEY', 'supersecretkey')
ALLOWED_NETWORKS = os.getenv('ALLOWED_NETWORKS', '127.0.0.1,::1')  # شبکه های مجاز به وب

app.secret_key = SECRET_KEY

INTERFACE_MARKS = {
    "1": {"interface": "Bridge- Local LAN", "routing_mark": "To-IranCell"},
    "2": {"interface": "Bridge- Local LAN", "routing_mark": "To-HamrahAval"},
    "3": {"interface": "Bridge- Local LAN", "routing_mark": "To-ADSL"},
    "4": {"interface": "Bridge- Local LAN", "routing_mark": "To-Anten"},
}

def ip_allowed(ip):
    allowed = [net.strip() for net in ALLOWED_NETWORKS.split(',')]
    for net in allowed:
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False

@app.before_request
def limit_remote_addr():
    user_ip = request.remote_addr
    if not ip_allowed(user_ip) and request.endpoint != 'login':
        abort(403, description="دسترسی از این شبکه مجاز نیست.")

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect('/login')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == WEB_PASSWORD:
            session['authenticated'] = True
            return redirect('/')
        else:
            return render_template('login.html', error="رمز عبور اشتباه است")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

def get_api_pool():
    return RouterOsApiPool(
        API_HOST,
        username=API_USER,
        password=API_PASS,
        port=API_PORT,
        plaintext_login=not API_USE_SSL,
        use_ssl=API_USE_SSL,
        ssl_verify=False  # در صورت نیاز ssl بدون تایید سرور
    )

@app.route('/check_api')
def check_api():
    if not session.get('authenticated'):
        return redirect('/login')
    try:
        api_pool = get_api_pool()
        api = api_pool.get_api()
        api_pool.disconnect()
        status = "اتصال به MikroTik برقرار است."
    except Exception as e:
        status = f"خطا در اتصال به MikroTik: {str(e)}"
    return render_template('check_api.html', status=status)

@app.route('/user_status')
def user_status():
    if not session.get('authenticated'):
        return redirect('/login')
    user_ip = request.remote_addr
    try:
        api_pool = get_api_pool()
        api = api_pool.get_api()
        mangles = api.get_resource('/ip/firewall/mangle')
        current_rule = None
        for m in mangles.get():
            if m.get('comment') == f"Internet Switcher {user_ip}":
                current_rule = m
                break
        api_pool.disconnect()
        if current_rule:
            routing_mark = current_rule.get('new-routing-mark', 'نامشخص')
        else:
            routing_mark = 'هیچ قانونی یافت نشد'
    except Exception as e:
        routing_mark = f"خطا در دریافت اطلاعات: {str(e)}"
    return render_template('user_status.html', routing_mark=routing_mark)

@app.route('/change_internet', methods=['GET', 'POST'])
def change_internet():
    if not session.get('authenticated'):
        return redirect('/login')
    user_ip = request.remote_addr
    message = ''
    if request.method == 'POST':
        inet = request.form.get('inet')
        if inet not in INTERFACE_MARKS:
            message = "اینترنت نامعتبر است"
        else:
            try:
                api_pool = get_api_pool()
                api = api_pool.get_api()
                mangles = api.get_resource('/ip/firewall/mangle')
                # حذف قوانین قبلی کاربر
                for m in mangles.get():
                    if m.get('comment') == f"Internet Switcher {user_ip}":
                        mangles.remove(id=m['.id'])
                # اضافه کردن قانون جدید
                mangles.add({
                    'chain': 'prerouting',
                    'src-address': user_ip,
                    'action': 'mark-routing',
                    'new-routing-mark': INTERFACE_MARKS[inet]['routing_mark'],
                    'passthrough': 'yes',
                    'comment': f"Internet Switcher {user_ip}"
                })
                api_pool.disconnect()
                message = "اینترنت شما با موفقیت تغییر یافت"
            except Exception as e:
                message = f"خطا در تغییر اینترنت: {str(e)}"
    return render_template('change_internet.html', message=message, interfaces=INTERFACE_MARKS)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=WEB_PORT)
