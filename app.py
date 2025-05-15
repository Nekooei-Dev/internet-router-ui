from flask import Flask, request, redirect, url_for, session, render_template
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

ALLOWED_NETWORK = os.getenv('ALLOWED_NETWORK', '192.168.88.')  # اجباری نیست، پیش‌فرض گذاشتم

@app.before_request
def restrict_to_local():
    ip = request.remote_addr
    if not ip.startswith(ALLOWED_NETWORK):
        return "دسترسی فقط برای کاربران شبکه داخلی مجاز است", 403

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('password') == WEB_PASSWORD:
            session['authenticated'] = True
            return redirect(url_for('index'))
        else:
            return "رمز عبور اشتباه است"
    return '''
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8" />
    <title>صفحه ورود</title>
</head>
<body>
    <form method="post">
        <label>رمز عبور: <input type="password" name="password" /></label>
        <button type="submit">ورود</button>
    </form>
</body>
</html>
'''

@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/set')
def set_internet():
    if not session.get('authenticated'):
        return "دسترسی غیرمجاز", 403

    inet = request.args.get('inet')
    if inet not in ['1', '2', '3', '4']:
        return "انتخاب نامعتبر", 400

    try:
        connection = RouterOsApiPool(
            host=API_HOST,
            username=API_USER,
            password=API_PASS,
            plaintext_login=True,
        )
        api = connection.get_api()

        # مثال ساده: فرض کنیم میخوایم route پیش‌فرض رو تغییر بدیم
        # حتما باید تنظیمات واقعی میکروتیک رو بر اساس اینترفیس‌های اینترنتت خودت جایگزین کنی
        # این فقط یک نمونه‌ی فرضیه‌ایه

        # حذف default route های قبلی
        api.get_resource('/ip/route').remove(where={'dst-address': '0.0.0.0/0'})

        # اضافه کردن default route جدید با انتخاب اینترفیس
        interface_map = {
            '1': 'ether1',
            '2': 'ether2',
            '3': 'ether3',
            '4': 'ether4',
        }

        new_route = {
            'dst-address': '0.0.0.0/0',
            'gateway': interface_map[inet],
        }
        api.get_resource('/ip/route').add(**new_route)

        connection.disconnect()
        return "OK"
    except Exception as e:
        return f"خطا: {e}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
