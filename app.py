import os
import json
import ipaddress
from functools import wraps
from flask import Flask, request, session, render_template, redirect, url_for, flash
from routeros_api import RouterOsApiPool, exceptions

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

# ---------- 📌 0. ذخیره و بارگذاری تنظیمات ----------
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {
        "routing_tables": {},
        "interfaces": {},
        "routes": {},
        "table_interface_map": {}
    }

def save_settings(settings):
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)

# ---------- 📌 1. IP کاربر ----------
def get_user_ip():
    return request.headers.get('X-Real-IP') or request.remote_addr

# ---------- 📌 2. اتصال API ----------
def connect_api():
    try:
        api_pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, port=API_PORT, plaintext_login=True)
        return api_pool.get_api()
    except exceptions.RouterOsApiConnectionError as e:
        print(f"❌ اتصال به میکروتیک ناموفق: {e}")
        return None

# ---------- 📌 3. لیست Routing Tables ----------
def fetch_routing_tables(api):
    return api.get_resource('/routing/table').get()

# ---------- 📌 4. لیست اینترفیس‌ها ----------
def fetch_interfaces(api):
    return api.get_resource('/interface/ethernet').get()

# ---------- 📌 5. حذف منگل کاربر ----------
def remove_user_mangle(api, user_ip):
    mangle = api.get_resource('/ip/firewall/mangle')
    rules = mangle.get()
    for rule in rules:
        comment = rule.get('comment', '')
        if comment in [f"user:{user_ip}", f"EXCEPTION: {user_ip}"]:
            mangle.remove(id=rule['id'])

# ---------- 📌 6. افزودن منگل برای کاربر ----------
def add_user_mangle(api, user_ip, routing_mark):
    mangle = api.get_resource('/ip/firewall/mangle')
    
    # حذف قوانین قبلی فقط برای اطمینان
    remove_user_mangle(api, user_ip)

    # ✅ اضافه کردن استثنا برای دسترسی به سایت و خود میکروتیک
    mangle.add(
        chain="prerouting",
        src_address=user_ip,
        dst_address=API_HOST,
        action="accept",
        comment=f"EXCEPTION: {user_ip}"
    )

    # 🔁 قانون اصلی با مارک روت
    mangle.add(
        chain='prerouting',
        src_address=user_ip,
        action='mark-routing',
        new_routing_mark=routing_mark,
        passthrough='yes',
        comment=f"user:{user_ip}"
    )

# ---------- 📌 7. روت پیش‌فرض ----------
def set_default_route(api, routing_table, gateway):
    routes = api.get_resource('/ip/route')
    routes.add(
        dst_address="0.0.0.0/0",
        gateway=gateway,
        routing_table=routing_table,
        check_gateway="ping"
    )

# ---------- 📌 8. ایجاد روت جدول-اینترفیس ----------
def create_table_routes(api, table_name, interface_name):
    ip_routes = api.get_resource('/ip/route')
    ip_routes.add(
        dst_address="0.0.0.0/0",
        gateway=interface_name,
        routing_table=table_name,
        check_gateway="ping"
    )

# ---------- 📌 9. دسترسی نقش ----------
def require_role(role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                flash("دسترسی غیرمجاز", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated
    return wrapper

# ---------- 📌 10. بررسی IP مجاز ----------
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
    except Exception as e:
        print(f"خطا در بررسی IP مجاز: {e}")
    return False

# ---------- 📌 11. گرفتن DHCP لیست ----------
def get_dhcp_leases(api):
    dhcp = api.get_resource("/ip/dhcp-server/lease")
    return dhcp.get()

# ---------- 📌 12. گرفتن روت پیش‌فرض ----------
def get_default_route(api):
    routes = api.get_resource('/ip/route').get()
    for r in routes:
        if r.get('dst-address') == '0.0.0.0/0' and 'routing-table' in r:
            return r['routing-table']
    return "main"

# ---------- 📌 13. اعمال روت‌ها از map ----------
def apply_table_routes(api, table_interface_map):
    route_res = api.get_resource('/ip/route')
    routes = route_res.get()

    for table, iface in table_interface_map.items():
        exists = any(r.get('routing-table') == table and r.get('gateway') == iface for r in routes)
        if not exists:
            try:
                route_res.add(
                    dst_address="0.0.0.0/0",
                    gateway=iface,
                    routing_table=table,
                    comment=f"auto-route:{table}"
                )
            except Exception as e:
                print(f"خطا در اضافه کردن روت برای جدول {table}: {e}")

# ---------- 📌 14. گرفتن گیت‌وی برای هر اینترفیس ----------
def get_interface_gateways(api):
    routes = api.get_resource("/ip/route").get()
    gateways = {}

    # 🧠 1. از روت‌ها
    for r in routes:
        iface = r.get("interface")
        gw = r.get("gateway")
        dst = r.get("dst-address")

        if iface and gw:
            gateways[iface] = gw

    # ✅ 2. از DHCP Client
    dhcp_clients = api.get_resource("/ip/dhcp-client").get()
    for client in dhcp_clients:
        iface = client.get("interface")
        gw = client.get("gateway")
        status = client.get("status")

        if iface and gw and status == "bound":
            gateways[iface] = gw

    return gateways

# ---------- 📌 صفحه اصلی ----------
@app.route("/")
def index():
    return redirect(url_for("login"))

# ---------- 📌 Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == WEB_ADMIN_PASSWORD:
            session['role'] = 'admin'
            return redirect(url_for('admin'))
        elif password == WEB_USER_PASSWORD:
            session['role'] = 'user'
            return redirect(url_for('user'))
        else:
            flash("رمز عبور اشتباه است", "danger")
    return render_template('login.html')

# ---------- 📌 Logout ----------
@app.route('/logout')
def logout():
    session.clear()
    flash("شما خارج شدید", "success")
    return redirect(url_for('login'))

# ---------- 📌 صفحه تنظیمات ادمین ----------
@app.route("/settings", methods=["GET", "POST"])
@require_role("admin")
def settings():
    api = connect_api()
    if not api:
        flash("عدم اتصال به API میکروتیک", "danger")
        return redirect(url_for('admin'))

    settings_data = load_settings()
    interfaces = fetch_interfaces(api)
    routing_tables = fetch_routing_tables(api)

    if request.method == "POST":
        new_interface_names = {}
        for iface in interfaces:
            iface_id = iface.get("name")
            friendly_name = request.form.get(f"iface_{iface_id}", "").strip()
            if friendly_name:
                new_interface_names[iface_id] = friendly_name

        new_routing_names = {}
        for table in routing_tables:
            table_name = table.get("name")
            friendly_name = request.form.get(f"table_{table_name}", "").strip()
            if friendly_name:
                new_routing_names[table_name] = friendly_name

        settings_data["interfaces"] = new_interface_names
        settings_data["routing_tables"] = new_routing_names

        save_settings(settings_data)
        flash("تنظیمات ذخیره شد.", "success")
        return redirect(url_for('settings'))

    return render_template('settings.html',
                           interfaces=interfaces,
                           routing_tables=routing_tables,
                           settings=settings_data)

# ---------- 📌 صفحه مدیریت ادمین ----------
@app.route("/admin", methods=["GET", "POST"])
@require_role("admin")
def admin():
    api = connect_api()
    if not api:
        flash("عدم اتصال به API میکروتیک", "danger")
        return render_template('admin.html')

    settings_data = load_settings()
    table_interface_map = settings_data.get("table_interface_map", {})

    if request.method == "POST":
        action = request.form.get("action")
        client_ip = request.form.get("ip_address", "").strip()

        # اعتبارسنجی IP
        if client_ip:
            try:
                ipaddress.ip_address(client_ip)
            except ValueError:
                flash("آی‌پی وارد شده معتبر نیست", "danger")
                return redirect(url_for('admin'))

        if action == "remove":
            if client_ip:
                remove_user_mangle(api, client_ip)
                flash(f"کاربر با آی‌پی {client_ip} حذف شد.", "success")
            else:
                flash("آی‌پی وارد نشده است.", "warning")

        elif action == "add":
            routing_table = request.form.get("routing_table")
            if not routing_table or routing_table not in table_interface_map:
                flash("جدول روت انتخاب شده نامعتبر است.", "danger")
            elif client_ip:
                routing_mark = routing_table
                add_user_mangle(api, client_ip, routing_mark)
                flash(f"کاربر با آی‌پی {client_ip} اضافه شد و روتینگ با جدول {routing_table} انجام شد.", "success")
            else:
                flash("آی‌پی وارد نشده است.", "warning")

        elif action == "apply_routes":
            apply_table_routes(api, table_interface_map)
            flash("روت‌ها به‌روزرسانی شدند.", "success")

        else:
            flash("عملیات نامعتبر است.", "danger")

        return redirect(url_for('admin'))

    # GET Request
    interfaces = fetch_interfaces(api)
    routing_tables = fetch_routing_tables(api)
    dhcp_leases = get_dhcp_leases(api)

    return render_template("admin.html",
                           interfaces=interfaces,
                           routing_tables=routing_tables,
                           dhcp_leases=dhcp_leases,
                           settings=settings_data)

# ---------- 📌 صفحه کاربر ----------
@app.route("/user", methods=["GET", "POST"])
@require_role("user")
def user():
    api = connect_api()
    if not api:
        flash("عدم اتصال به API میکروتیک", "danger")
        return render_template('user.html')

    user_ip = get_user_ip()

    # بررسی دسترسی IP
    if not is_allowed_network(user_ip):
        flash(f"آی‌پی شما ({user_ip}) مجاز نیست.", "danger")
        session.clear()
        return redirect(url_for('login'))

    settings_data = load_settings()
    table_interface_map = settings_data.get("table_interface_map", {})
    default_table = get_default_route(api)

    if request.method == "POST":
        routing_table = request.form.get("routing_table")
        if routing_table not in table_interface_map:
            flash("جدول روت انتخاب شده نامعتبر است.", "danger")
            return redirect(url_for('user'))

        add_user_mangle(api, user_ip, routing_table)
        flash(f"تغییر اینترنت با جدول {routing_table} برای شما اعمال شد.", "success")
        return redirect(url_for('user'))

    return render_template("user.html",
                           user_ip=user_ip,
                           tables=table_interface_map,
                           default_table=default_table)

# ---------- 📌 صفحه اصلی ادمین ----------
@app.route("/admin_dashboard")
@require_role("admin")
def admin_dashboard():
    api = connect_api()
    if not api:
        flash("عدم اتصال به API میکروتیک", "danger")
        return redirect(url_for('login'))

    settings_data = load_settings()
    table_interface_map = settings_data.get("table_interface_map", {})
    interfaces = fetch_interfaces(api)
    routing_tables = fetch_routing_tables(api)

    return render_template('admin_dashboard.html',
                           interfaces=interfaces,
                           routing_tables=routing_tables,
                           table_interface_map=table_interface_map)

# ---------- 📌 صفحه خطا (اختیاری) ----------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

# ---------- 📌 اجرا ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
