import os
import json
from flask import Flask, request, session
from routeros_api import RouterOsApiPool, exceptions
import ipaddress

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "9f7e2c45b6a14d9a8e4d31f0c5b2a7e1")

API_HOST = os.environ.get("API_HOST", "172.30.30.254")
API_USER = os.environ.get("API_USER", "API")
API_PASS = os.environ.get("API_PASS", "API")
API_PORT = int(os.environ.get("API_PORT", 8728))

SETTINGS_FILE = "settings.json"

WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")

ALLOWED_NETWORKS = [net.strip() for net in os.environ.get(
    "ALLOWED_NETWORKS",
    "172.30.30.0/24 , 172.32.30.10-172.32.30.40 , 192.168.1.10"
).split(",")]




### 📌 0. ذخیره و بارگذاری تنظیمات اولیه
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {
        "routing_tables": {},
        "interfaces": {},
        "routes": {}
    }

def save_settings(settings):
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)


### 📌 1. گرفتن IP کاربری که لاگین کرده
def get_user_ip():
    return request.headers.get('X-Real-IP') or request.remote_addr


### 📌 2. اتصال به میکروتیک
def connect_api():
    try:
        api_pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, port=API_PORT, plaintext_login=True)
        return api_pool.get_api()
    except exceptions.RouterOsApiConnectionError as e:
        print(f"❌ اتصال به میکروتیک ناموفق: {e}")
        return None

### 📌 3. دریافت لیست Routing Tableها
def fetch_routing_tables(api):
    return api.get_resource('/routing/table').get()


### 📌 4. دریافت لیست اینترفیس‌ها
def fetch_interfaces(api):
    return api.get_resource('/interface/ethernet').get()

### 📌 5. حذف قوانین منگل یک کاربر
def remove_user_mangle(api, user_ip):
    mangle = api.get_resource('/ip/firewall/mangle')
    rules = mangle.get()
    for rule in rules:
        if rule.get('comment') == f"user:{user_ip}":
            mangle.remove(id=rule['id'])


### 📌 6. افزودن منگل برای کاربر
def add_user_mangle(api, user_ip, routing_mark):
    mangle = api.get_resource('/ip/firewall/mangle')
    mangle.add(
        chain='prerouting',
        src_address=user_ip,
        action='mark-routing',
        new_routing_mark=routing_mark,
        passthrough='yes',
        comment=f"user:{user_ip}"
    )

### 📌 7. افزودن default route برای جدول خاص
def set_default_route(api, routing_table, gateway):
    routes = api.get_resource('/ip/route')
    routes.add(
        dst_address="0.0.0.0/0",
        gateway=gateway,
        routing_table=routing_table,
        check_gateway="ping"
    )

### 📌 8. تنظیم جدول برای اینترفیس‌ها (route per interface)
def create_table_routes(api, table_name, interface_name):
    ip_routes = api.get_resource('/ip/route')
    ip_routes.add(
        dst_address="0.0.0.0/0",
        gateway=interface_name,
        routing_table=table_name,
        check_gateway="ping"
    )

### 📌 9. بررسی دسترسی صفحات بر اساس نقش
def require_role(role):
    def wrapper(f):
        def decorated(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                return "Access denied", 403
            return f(*args, **kwargs)
        return decorated
    return wrapper

### 📌 10. بررسی IP مجاز بودن کاربر (بر اساس ALLOWED_NETWORKS)
ALLOWED_NETWORKS = [ip.strip() for ip in os.environ.get(
    "ALLOWED_NETWORKS", "172.30.30.0/24 , 192.168.1.0/24").split(",")]

def is_allowed_network(ip):
    try:
        ip_addr = ipaddress.ip_address(ip)
        for net in ALLOWED_NETWORKS:
            if "-" in net:
                start_ip, end_ip = net.split("-")
                if ipaddress.ip_address(start_ip) <= ip_addr <= ipaddress.ip_address(end_ip):
                    return True
            else:
                net_obj = ipaddress.ip_network(net.strip(), strict=False)
                if ip_addr in net_obj:
                    return True
    except Exception:
        return False
    return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == WEB_ADMIN_PASSWORD:
            session['role'] = 'admin'
            return redirect(url_for('index'))
        elif password == WEB_USER_PASSWORD:
            session['role'] = 'user'
            return redirect(url_for('index'))
        else:
            flash("رمز عبور اشتباه است", "danger")
    return render_template('login.html')


from flask import render_template, redirect, url_for, flash



@app.route("/settings", methods=["GET", "POST"])
@require_role("admin")
def settings():
    api = connect_api()
    if not api:
        return render_template("error.html", message="عدم اتصال به API میکروتیک")

    settings_data = load_settings()
    interfaces = fetch_interfaces(api)
    routing_tables = fetch_routing_tables(api)

    if request.method == "POST":
        # ذخیره‌سازی نام‌های دوستانه اینترفیس‌ها
        new_interface_names = {}
        for iface in interfaces:
            iface_id = iface.get("name")
            friendly_name = request.form.get(f"iface_{iface_id}", "").strip()
            if friendly_name:
                new_interface_names[iface_id] = friendly_name

        # ذخیره‌سازی نام‌های دوستانه روت‌تیبل‌ها
        new_routing_names = {}
        for table in routing_tables:
            table_id = table.get("name")
            friendly_name = request.form.get(f"table_{table_id}", "").strip()
            if friendly_name:
                new_routing_names[table_id] = friendly_name

        settings_data["interfaces"] = new_interface_names
        settings_data["routing_tables"] = new_routing_names
        save_settings(settings_data)

        flash("تنظیمات با موفقیت ذخیره شد", "success")
        return redirect(url_for("settings"))

    return render_template(
        "settings.html",
        interfaces=interfaces,
        routing_tables=routing_tables,
        settings=settings_data
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
