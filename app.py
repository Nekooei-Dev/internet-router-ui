from flask import Flask, request, session, redirect, render_template
from routeros_api import RouterOsApiPool
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'changeme')

API_HOST = os.getenv('API_HOST', '172.30.30.254')
API_USER = os.getenv('API_USER', 'API')
API_PASS = os.getenv('API_PASS', 'API@Mostafa')
ALLOWED_NETWORKS = os.getenv('ALLOWED_NETWORKS', '172.30.30.0/24').split(',')

INTERFACE_MARKS = {
    "1": {"routing_mark": "To-IranCell"},
    "2": {"routing_mark": "To-HamrahAval"},
    "3": {"routing_mark": "To-ADSL"},
    "4": {"routing_mark": "To-Anten"},
}

@app.before_request
def restrict_to_local():
    ip = request.remote_addr
    if not any(ip.startswith(net.strip().rsplit('.', 1)[0]) for net in ALLOWED_NETWORKS):
        return "دسترسی فقط برای کاربران شبکه داخلی مجاز است", 403

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect('/login')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == os.getenv('WEB_PASSWORD', '123456'):
            session['authenticated'] = True
            return redirect('/')
        else:
            return "رمز عبور اشتباه است"
    return render_template('login.html')

@app.route('/set')
def set_internet():
    if not session.get('authenticated'):
        return "لطفا وارد شوید", 401

    inet = request.args.get('inet')
    if inet not in INTERFACE_MARKS:
        return "اینترنت نامعتبر است", 400

    user_ip = request.remote_addr

    try:
        api_pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS)
        api = api_pool.get_api()

        mangle = api.get_resource('/ip/firewall/mangle')

        # حذف قوانین قدیمی کاربر
        for rule in mangle.get():
            if rule.get('comment') == f"Internet Switcher {user_ip}":
                mangle.remove(id=rule['.id'])

        # افزودن قانون جدید
        mangle.add({
            'chain': 'prerouting',
            'src-address': user_ip,
            'action': 'mark-routing',
            'new-routing-mark': INTERFACE_MARKS[inet]['routing_mark'],
            'passthrough': 'yes',
            'comment': f"Internet Switcher {user_ip}"
        })

        api_pool.disconnect()
        return "اینترنت شما با موفقیت تغییر یافت"

    except Exception as e:
        return f"خطا در تغییر اینترنت: {str(e)}", 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.getenv('WEB_PORT', '5000')))
