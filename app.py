import os
from flask import Flask, render_template, request, redirect, session
from routeros_api import RouterOsApiPool

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# خواندن متغیرهای محیطی با مقدار پیش‌فرض
API_HOST = os.getenv('MIKROTIK_HOST', '172.30.30.254')
API_USER = os.getenv('MIKROTIK_USER', 'API')
API_PASS = os.getenv('MIKROTIK_PASS', 'API')
API_PORT = int(os.getenv('MIKROTIK_PORT', '8728'))

INTERFACE_MARKS = {
    "1": {"interface": "Bridge- Local LAN", "routing_mark": "To-IranCell"},
    "2": {"interface": "Bridge- Local LAN", "routing_mark": "To-HamrahAval"},
    "3": {"interface": "Bridge- Local LAN", "routing_mark": "To-ADSL"},
    "4": {"interface": "Bridge- Local LAN", "routing_mark": "To-Anten"},
}

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect('/login')
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == '123456':
            session['authenticated'] = True
            return redirect('/')
        else:
            return render_template('login.html', error="رمز عبور اشتباه است")
    return render_template('login.html')

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
            username=API_USER,
            password=API_PASS,
            port=API_PORT,
            plaintext_login=True
        )
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
        api_pool = RouterOsApiPool(
            API_HOST,
            username=API_USER,
            password=API_PASS,
            port=API_PORT,
            plaintext_login=True
        )
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
                api_pool = RouterOsApiPool(
                    API_HOST,
                    username=API_USER,
                    password=API_PASS,
                    port=API_PORT,
                    plaintext_login=True
                )
                api = api_pool.get_api()
                mangles = api.get_resource('/ip/firewall/mangle')
                for m in mangles.get():
                    if m.get('comment') == f"Internet Switcher {user_ip}":
                        mangles.remove(id=m['.id'])
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
    app.run(host='0.0.0.0', port=5000)
