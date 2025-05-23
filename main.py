from flask import Flask, render_template, request, jsonify, redirect, url_for
from mikrotik_api import MikrotikAPI
import json
import os
import base64

app = Flask(__name__)

SETTINGS_FILE = 'settings.json'

def encode_password(password):
    return base64.b64encode(password.encode('utf-8')).decode('utf-8')

def decode_password(encoded):
    return base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
    
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            settings = json.load(f)
            if settings.get('password'):
                settings['password'] = decode_password(settings['password'])
            return settings
    else:
        return {"ip": "", "username": "", "password": "", "interface": ""}

def save_settings(settings):
    settings_to_save = settings.copy()
    if settings_to_save.get('password'):
        settings_to_save['password'] = encode_password(settings_to_save['password'])
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings_to_save, f, ensure_ascii=False, indent=4)

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
