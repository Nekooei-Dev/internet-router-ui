import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from routeros_api import RouterOsApiPool
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')

API_HOST = os.getenv('API_HOST', '192.168.88.1')
API_USER = os.getenv('API_USER', 'admin')
API_PASS = os.getenv('API_PASS', 'password')
WEB_PASSWORD = os.getenv('WEB_PASSWORD', '123456')
ALLOWED_NETWORKS = os.getenv('ALLOWED_NETWORKS', '192.168.88.0/24').split(',')

INTERFACE_MARKS = {
    "1": {"interface": "Bridge-Local-LAN", "routing_mark": "To-IranCell"},
    "2": {"interface": "Bridge-Local-LAN", "routing_mark": "To-HamrahAval"},
    "3": {"interface": "Bridge-Local-LAN", "routing_mark": "To-ADSL"},
    "4": {"interface": "Bridge-Local-LAN", "routing_mark": "To-Anten"},
}

def is_ip_allowed(ip):
    return any(ip.startswith(net.strip().rsplit('.', 1)[0]) for net in ALLOWED_NETWORKS)

def get_api_connection():
    try:
        api_pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS)
        api = api_pool.get_api()
        return api, api_pool
    except Exception as e:
        return None, None

@app.before_request
def restrict_to_local():
    ip = request.remote_addr
    if not is_ip_allowed(ip):
        return "دسترسی فقط برای کاربران شبکه داخلی مجاز است", 403

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == WEB_PASSWORD:
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        else:
            flash("رمز عبور اشتباه است")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/check_api')
def check_api():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    api, api_pool = get_api_connection()
    if api:
        api_pool.disconnect()
        status = "اتصال به MikroTik برقرار است."
    else:
        status = "خطا در اتصال به MikroTik."
    return render_template('check_api.html', status=status)

@app.route('/users')
def users():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    api, api_pool = get_api_connection()
    if not api:
        flash("خطا در اتصال به MikroTik.")
        return redirect(url_for('dashboard'))
    mangles = api.get_resource('/ip/firewall/mangle')
    rules = mangles.get()
    user_rules = [rule for rule in rules if rule.get('comment', '').startswith('Internet Switcher')]
    api_pool.disconnect()
    return render_template('users.html', rules=user_rules)

@app.route('/delete_user/<rule_id>')
def delete_user(rule_id):
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    api, api_pool = get_api_connection()
    if not api:
        flash("خطا در اتصال به MikroTik.")
        return redirect(url_for('users'))
    mangles = api.get_resource('/ip/firewall/mangle')
    try:
        mangles.remove(id=rule_id)
        flash("قانون با موفقیت حذف شد.")
    except Exception as e:
        flash(f"خطا در حذف قانون: {str(e)}")
    api_pool.disconnect()
    return redirect(url_for('users'))

@app.route('/change_internet', methods=['GET', 'POST'])
def change_internet():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    user_ip = request.remote_addr
    current_inet = "نامشخص"
    api, api_pool = get_api_connection()
    if not api:
        flash("خطا در اتصال به MikroTik.")
        return redirect(url_for('dashboard'))
    mangles = api.get_resource('/ip/firewall/mangle')
    rules = mangles.get()
    for rule in rules:
        if rule.get('comment') == f"Internet Switcher {user_ip}":
            current_inet = rule.get('new-routing-mark', 'نامشخص')
            break
    if request.method == 'POST':
        inet = request.form.get('inet')
        if inet not in INTERFACE_MARKS:
            flash("اینترنت نامعتبر است.")
            return redirect(url_for('change_internet'))
        # حذف قوانین قبلی برای این IP
        for rule in rules:
            if rule.get('comment') == f"Internet Switcher {user_ip}":
                mangles.remove(id=rule['.id'])
        # افزودن قانون جدید
        try:
            mangles.add({
                'chain': 'prerouting',
                'src-address': user_ip,
                'action': 'mark-routing',
                'new-routing-mark': INTERFACE_MARKS[inet]['routing_mark'],
                'passthrough': 'yes',
                'comment': f"Internet Switcher {user_ip}"
            })
            flash("اینترنت شما با موفقیت تغییر یافت.")
            current_inet = INTERFACE_MARKS[inet]['routing_mark']
        except Exception as e:
            flash(f"خطا در تغییر اینترنت: {str(e)}")
    api_pool.disconnect()
    return render_template('change_internet.html', current_inet=current_inet, interfaces=INTERFACE_MARKS)
