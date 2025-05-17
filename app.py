from flask import Flask, render_template, request, redirect, session, abort, url_for
import os
import routeros_api
import ipaddress

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "defaultsecret")

# میکروتیک API
API_HOST = os.environ.get("API_HOST")
API_USER = os.environ.get("API_USER")
API_PASS = os.environ.get("API_PASS")
API_PORT = int(os.environ.get("API_PORT", 8728))

# احراز هویت
WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")

# کنترل دسترسی آی‌پی
ALLOWED_NETWORKS = os.environ.get("ALLOWED_NETWORKS", "").split(",")


def is_ip_allowed(ip):
    for net in ALLOWED_NETWORKS:
        if '-' in net:
            start, end = net.split('-')
            if ipaddress.IPv4Address(start) <= ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(end):
                return True
        else:
            if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(net, strict=False):
                return True
    return False


@app.before_request
def limit_remote_addr():
    if not is_ip_allowed(request.remote_addr):
        abort(403)


def get_api():
    try:
        pool = routeros_api.RouterOsApiPool(
            host=API_HOST,
            username=API_USER,
            password=API_PASS,
            port=API_PORT,
            plaintext_login=True
        )
        return pool.get_api(), pool
    except Exception as e:
        print("API connection error:", e)
        return None, None


def is_logged_in():
    return 'logged_in' in session


@app.route('/', methods=['GET'])
def index():
    api, pool = get_api()
    api_ok = bool(api)
    if pool:
        pool.disconnect()
    return render_template('index.html', api_ok=api_ok)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        pw = request.form.get('password')
        if pw in [WEB_USER_PASSWORD, WEB_ADMIN_PASSWORD]:
            session['logged_in'] = True
            session['is_admin'] = (pw == WEB_ADMIN_PASSWORD)
            return redirect(url_for('index'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/admin')
def admin():
    if not is_logged_in() or not session.get('is_admin'):
        return redirect(url_for('login'))
    # TODO: افزودن لیست کاربران و اینترنت فعلی‌شان
    return render_template('admin.html')


@app.route('/change_internet', methods=['GET', 'POST'])
def change_internet():
    if not is_logged_in():
        return redirect(url_for('login'))
    # TODO: پیاده‌سازی تغییر اینترنت برای آی‌پی کاربر
    return render_template('change_internet.html')


@app.route('/user_status')
def user_status():
    if not is_logged_in():
        return redirect(url_for('login'))
    # TODO: بررسی اینکه کاربر به کدام اینترنت متصل است
    return render_template('user_status.html')


@app.route('/about')
def about():
    return render_template('about.html')
