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
    "1": {"name": "Irancell", "routing_mark": "To-IranCell"},
    "2": {"name": "Hamrah Aval", "routing_mark": "To-HamrahAval"},
    "3": {"name": "ADSL", "routing_mark": "To-ADSL"},
    "4": {"name": "Anten", "routing_mark": "To-Anten"},
}

def get_api_connection():
    try:
        api = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, plaintext_login=True)
        return api, api.get_api()
    except Exception as e:
        return None, None

@app.before_request
def restrict_to_local():
    ip = request.remote_addr
    if not any(ip.startswith(net.strip().rsplit('.', 1)[0]) for net in ALLOWED_NETWORKS):
        return "دسترسی فقط برای کاربران شبکه داخلی مجاز است", 403

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect('/login')

    user_ip = request.remote_addr
    current_inet = None

    try:
        api_pool, api = get_api_connection()
        if not api:
            return "ارتباط با MikroTik برقرار نشد", 500

        mangles = api.get_resource('/ip/firewall/mangle').get()
        for m in mangles:
            if m.get('src-address') == user_ip and m.get('action') == 'mark-routing':
                current_inet = next((key for key, val in INTERFACE_MARKS.items() if val["routing_mark"] == m.get('new-routing-mark')), None)
                break

        api_pool.disconnect()
    except Exception as e:
        return f"خطا در دریافت وضعیت اینترنت: {str(e)}", 500

    return render_template('index.html', current_inet=current_inet, interface_marks=INTERFACE_MARKS)

@app.route('/login', methods=['GET', 'POST'])
def login():
    api_ok = False
    try:
        api_pool, api = get_api_connection()
        if api:
            api_pool.disconnect()
            api_ok = True
    except:
        api_ok = False

    if request.method == 'POST':
        if not api_ok:
            return "عدم دسترسی به MikroTik. لطفاً بررسی شود.", 500

        if request.form.get('password') == os.getenv('WEB_PASSWORD', '123456'):
            session['authenticated'] = True
            return redirect('/')
        else:
            return "رمز عبور اشتباه است"

    return render_template('login.html', api_ok=api_ok)

@app.route('/set')
def set_internet():
    if not session.get('authenticated'):
        return "لطفا وارد شوید", 401

    inet = request.args.get('inet')
    if inet not in INTERFACE_MARKS:
        return "اینترنت نامعتبر است", 400

    user_ip = request.remote_addr

    try:
        api_pool, api = get_api_connection()
        if not api:
            return "عدم اتصال به MikroTik", 500

        mangles = api.get_resource('/ip/firewall/mangle')

        # Remove previous rules
        for m in mangles.get():
            if m.get('comment') == f"Internet Switcher {user_ip}":
                mangles.remove(id=m['.id'])

        # Add rule for current user IP
        mangles.add({
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
