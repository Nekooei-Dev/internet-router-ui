from flask import Flask, render_template, request, jsonify, redirect, url_for
from mikrotik_api import MikrotikAPI
import json
import os

app = Flask(__name__)

SETTINGS_FILE = 'settings.json'

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    else:
        return {"ip": "", "username": "", "password": "", "interface": ""}

def save_settings(settings):
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings, f, ensure_ascii=False, indent=4)

@app.route('/')
def index():
    settings = load_settings()
    return render_template('index.html', settings=settings)

@app.route('/update_mangle', methods=['POST'])
def update_mangle():
    settings = load_settings()
    ip = settings.get('ip')
    username = settings.get('username')
    password = settings.get('password')
    interface = settings.get('interface')

    if not all([ip, username, password, interface]):
        return jsonify({"error": "تنظیمات اتصال کامل نیست. لطفا ابتدا تنظیمات را وارد کنید."})

    user_ip = request.form.get('user_ip', '').strip()
    comment = request.form.get('comment', '').strip()

    if not user_ip:
        return jsonify({"error": "آدرس IP وارد نشده است."})

    api = MikrotikAPI(ip, username, password)
    try:
        api.connect()
        # حذف قوانین قبلی با کامنت مشابه
        api.remove_mangle_rules(comment)
        # افزودن قانون جدید
        api.add_mangle_rule(user_ip, interface, comment)
        api.disconnect()
    except Exception as e:
        return jsonify({"error": f"خطا در ارتباط با میکروتیک: {str(e)}"})

    return jsonify({"success": "قانون Mangle با موفقیت اضافه شد."})

@app.route('/settings', methods=['GET', 'POST'])
def configure_settings():
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        interface = request.form.get('interface', '').strip()

        if not all([ip, username, password, interface]):
            error = "لطفا همه فیلدها را تکمیل کنید."
            return render_template('settings.html', settings=request.form, error=error)

        save_settings({
            "ip": ip,
            "username": username,
            "password": password,
            "interface": interface
        })
        return redirect(url_for('index'))

    settings = load_settings()
    return render_template('settings.html', settings=settings)

if __name__ == '__main__':
    app.run(debug=True)
