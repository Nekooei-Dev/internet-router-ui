import os
from flask import Flask, render_template, request, redirect, session, abort
from routeros_api import RouterOsApiPool
import ipaddress

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret')

# پیکربندی از متغیرهای محیطی
API_HOST = os.getenv('API_HOST', '172.30.30.254')
API_USER = os.getenv('API_USER', 'API')
API_PASS = os.getenv('API_PASS', 'API')
API_PORT = int(os.getenv('API_PORT', 8728))
API_USE_SSL = os.getenv('API_USE_SSL', 'false').lower() == 'true'

WEB_PASSWORD = os.getenv('WEB_PASSWORD', '123456')
WEB_PORT = int(os.getenv('WEB_PORT', 5000))
ALLOWED_NETWORKS = os.getenv('ALLOWED_NETWORKS', '0.0.0.0/0').split(',')

# اینترنت‌ها و مارک‌های مسیریابی
INTERFACE_MARKS = {
    "1": {"name": "ایرانسل", "routing_mark": "To-IranCell"},
    "2": {"name": "همراه اول", "routing_mark": "To-HamrahAval"},
    "3": {"name": "ADSL", "routing_mark": "To-ADSL"},
    "4": {"name": "آنتن", "routing_mark": "To-Anten"},
}

# بررسی دسترسی IP به برنامه
@app.before_request
def limit_remote_addr():
    remote_ip = ipaddress.ip_address(request.remote_addr)
    allowed = any(remote_ip in ipaddress.ip_network(net.strip()) for net in ALLOWED_NETWORKS)
    if not allowed:
        abort(403)

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect('/login')
    return render_template('index.html', interfaces=INTERFACE_MARKS)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form.get('password') == WEB_PASSWORD:
            session['authenticated'] = True
            return redirect('/')
        else:
            error = "رمز عبور اشتباه است"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/check_api')
def check_api():
    if not session.get('authenticated'):
        return redirect('/login')
    try:
        api_pool = RouterOsApiPool(
            API_HOST,
            API_USER,
            API_PASS,
            port=API_PORT,
            use_ssl=API_USE_SSL,
            plaintext_login=True
        )
        api = api_pool.get_api()
        api.get_binary_resource('/system/resource').call('print')
        api_pool.disconnect()
        status = "✅ اتصال با موفقیت برقرار شد."
    except Exception as e:
        status = f"❌ خطا در اتصال به MikroTik: {e}"
    return render_template('check_api.html', status=status)

@app.route('/user_status')
def user_status():
    if not session.get('authenticated'):
        return redirect('/login')
    user_ip = request.remote_addr
    try:
        api_pool = RouterOsApiPool(
            API_HOST,
            API_USER,
            API_PASS,
            port=API_PORT,
            use_ssl=API_USE_SSL,
            plaintext_login=True
        )
        api = api_pool.get_api()
        mangles = api.get_resource('/ip/firewall/mangle')
        current_rule = next((m for m in mangles.get() if m.get('comment') == f"Internet Switcher {user_ip}"), None)
        api_pool.disconnect()
        routing_mark = current_rule.get('new-routing-mark') if current_rule else 'هیچ قانونی برای شما پیدا نشد.'
    except Exception as e:
        routing_mark = f"خطا در دریافت اطلاعات: {e}"
    return render_template('user_status.html', routing_mark=routing_mark)

@app.route('/change_internet', methods=['GET', 'POST'])
def change_internet():
    if not session.get('authenticated'):
        return redirect('/login')

    user_ip = request.remote_addr
    message = None

    if request.method == 'POST':
        selected = request.form.get('inet')
        if selected not in INTERFACE_MARKS:
            message = "اینترنت انتخاب‌شده نامعتبر است."
        else:
            try:
                api_pool = RouterOsApiPool(
                    API_HOST,
                    API_USER,
                    API_PASS,
                    port=API_PORT,
                    use_ssl=API_USE_SSL,
                    plaintext_login=True
                )
                api = api_pool.get_api()
                mangles = api.get_resource('/ip/firewall/mangle')

                # حذف قوانین قبلی کاربر
                for m in mangles.get():
                    if m.get('comment') == f"Internet Switcher {user_ip}":
                        mangles.remove({'id': m['.id']})

                # اضافه کردن قانون جدید
                mangles.add({
                    'chain': 'prerouting',
                    'src-address': user_ip,
                    'action': 'mark-routing',
                    'new-routing-mark': INTERFACE_MARKS[selected]['routing_mark'],
                    'passthrough': 'yes',
                    'comment': f"Internet Switcher {user_ip}"
                })
                api_pool.disconnect()
                message = "✅ اینترنت شما با موفقیت تغییر یافت."
            except Exception as e:
                message = f"❌ خطا در تغییر اینترنت: {e}"

    return render_template('change_internet.html', message=message, interfaces=INTERFACE_MARKS)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=WEB_PORT)
