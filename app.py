import os
from flask import Flask, render_template, request, redirect, session
from librouteros import connect
from librouteros.exceptions import TrapError

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# متغیرهای محیطی
API_HOST = os.environ.get('API_HOST', '172.30.30.254')
API_USER = os.environ.get('API_USER', 'API')
API_PASS = os.environ.get('API_PASS', 'API')
API_PORT = int(os.environ.get('API_PORT', 8729))
API_USE_SSL = os.environ.get('API_USE_SSL', 'false').lower() == 'true'

WEB_PASSWORD = os.environ.get('WEB_PASSWORD', '123456')
WEB_PORT = int(os.environ.get('WEB_PORT', 5000))

INTERFACE_MARKS = {
    "1": {"routing_mark": "To-IranCell"},
    "2": {"routing_mark": "To-HamrahAval"},
    "3": {"routing_mark": "To-ADSL"},
    "4": {"routing_mark": "To-Anten"},
}

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

@app.route('/check_api')
def check_api():
    if not session.get('authenticated'):
        return redirect('/login')
    try:
        print("[DEBUG] Trying API connection...")
        api = connect(username=API_USER, password=API_PASS, host=API_HOST, port=API_PORT, use_ssl=API_USE_SSL)
        list(api(cmd='/system/resource/print'))
        status = "✅ اتصال به MikroTik برقرار است."
    except Exception as e:
        status = f"❌ خطا در اتصال به MikroTik: {str(e)}"
    return render_template('check_api.html', status=status)

@app.route('/user_status')
def user_status():
    if not session.get('authenticated'):
        return redirect('/login')

    user_ip = request.remote_addr
    routing_mark = 'هیچ قانونی یافت نشد'
    try:
        print(f"[DEBUG] Checking user status for IP: {user_ip}")
        api = connect(username=API_USER, password=API_PASS, host=API_HOST, port=API_PORT, use_ssl=API_USE_SSL)
        mangles = api(cmd='/ip/firewall/mangle/print')

        for rule in mangles:
            if rule.get('comment') == f"Internet Switcher {user_ip}":
                routing_mark = rule.get('new-routing-mark', 'نامشخص')
                break
    except Exception as e:
        routing_mark = f"❌ خطا در دریافت اطلاعات: {str(e)}"

    return render_template('user_status.html', routing_mark=routing_mark)

@app.route('/change_internet', methods=['GET', 'POST'])
def change_internet():
    if not session.get('authenticated'):
        return redirect('/login')

    user_ip = request.remote_addr
    message = ''

    if request.method == 'POST':
        inet = request.form.get('inet')
        print(f"[DEBUG] User IP: {user_ip}, Selected Internet: {inet}")

        if inet not in INTERFACE_MARKS:
            message = "❌ اینترنت انتخاب شده نامعتبر است"
        else:
            try:
                api = connect(username=API_USER, password=API_PASS, host=API_HOST, port=API_PORT, use_ssl=API_USE_SSL)

                print("[DEBUG] Rule that is about to be added:")
                for k, v in rule_data.items():
                print(f"{k} = {v}")

                mangle = api(cmd='/ip/firewall/mangle/print')

                # حذف قوانین قبلی برای کاربر
                for rule in mangle:
                    if rule.get('comment') == f"Internet Switcher {user_ip}":
                        print(f"[DEBUG] Removing existing rule with ID: {rule['.id']}")

                        
                        print("[DEBUG] Rule that is about to be added:")
                        for k, v in rule_data.items():
                        print(f"{k} = {v}")

                        
                        api(cmd='/ip/firewall/mangle/remove', **{'.id': rule['.id']})

                # قانون جدید
                rule_data = {
                    'chain': 'prerouting',
                    'src-address': user_ip,
                    'action': 'mark-routing',
                    'new-routing-mark': INTERFACE_MARKS[inet]['routing_mark'],
                    'passthrough': 'yes',
                    'comment': f"Internet Switcher {user_ip}"
                }

                print(f"[DEBUG] Adding rule: {rule_data}")

                print("[DEBUG] Rule that is about to be added:")
                for k, v in rule_data.items():
                print(f"{k} = {v}")  
                
                api(cmd='/ip/firewall/mangle/add', **rule_data)

                message = "✅ اینترنت شما با موفقیت تغییر یافت."

            except TrapError as e:
                message = f"❌ خطا در تغییر اینترنت (MikroTik Trap): {str(e)}"
                print(f"[ERROR] TrapError: {str(e)}")
            except Exception as e:
                message = f"❌ خطا در تغییر اینترنت: {str(e)}"
                print(f"[ERROR] General Exception: {str(e)}")

    return render_template('change_internet.html', message=message, interfaces=INTERFACE_MARKS)

if __name__ == '__main__':
    print("[INFO] Starting Flask app...")
    app.run(host='0.0.0.0', port=WEB_PORT)
