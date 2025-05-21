import os
import json
import ipaddress
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
        def decorated(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                return "Access denied", 403
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
    except Exception:
        return False
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

# ---------- 📌 صفحه تنظیمات ادمین ----------
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
        new_interface_names = {}
        for iface in interfaces:
            iface_id = iface.get("name")
            friendly_name = request.form.get(f"iface_{iface_id}", "").strip()
            if friendly_name:
                new_interface_names[iface_id] = friendly_name

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

# ---------- 📌 صفحه کاربر ----------
@app.route('/user', methods=['GET', 'POST'])
def user():
    if 'role' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    api = connect_api()
    if not api:
        return render_template('error.html', message="ارتباط با میکروتیک برقرار نشد")

    user_ip = get_user_ip()
    if not is_allowed_network(user_ip):
        return render_template('error.html', message="آی‌پی شما مجاز نیست")

    leases = get_dhcp_leases(api)
    user_lease = next((lease for lease in leases if lease.get('address') == user_ip), None)

    settings_data = load_settings()
    routing_tables = fetch_routing_tables(api)

    friendly_tables = [
        {
            "id": tbl["name"],
            "name": settings_data.get("routing_tables", {}).get(tbl["name"], tbl["name"])
        } for tbl in routing_tables
    ]

    if request.method == 'POST':
        selected_table = request.form.get('internet_table')
        valid_ids = [tbl["name"] for tbl in routing_tables]  # اصلاح شده ✅

        if selected_table not in valid_ids:
            flash("تیبل انتخابی نامعتبر است", "danger")
        else:
            try:
                remove_user_mangle(api, user_ip)
                add_user_mangle(api, user_ip, selected_table)
                flash("اینترنت شما با موفقیت تغییر کرد", "success")
            except Exception as e:
                flash(f"خطا در تغییر اینترنت: {e}", "danger")

    return render_template('user.html', user_ip=user_ip, user_lease=user_lease, tables=friendly_tables)

# ---------- 📌 صفحه ادمین ----------
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    api = connect_api()
    if not api:
        return render_template('error.html', message="ارتباط با میکروتیک برقرار نشد")

    settings_data = load_settings()
    table_interface_map = settings_data.get("table_interface_map", {})
    leases = get_dhcp_leases(api)
    routing_tables = fetch_routing_tables(api)
    default_route = get_default_route(api)

    friendly_tables = [
        {
            "id": tbl["name"],
            "name": settings_data.get("routing_tables", {}).get(tbl["name"], tbl["name"])
        } for tbl in routing_tables
    ]

    if request.method == 'POST':
        client_ip = request.form.get('client_ip')
        valid_tables = [t["name"] for t in routing_tables]  # اصلاح شده ✅

        if 'change_internet' in request.form:
            new_internet = request.form.get('new_internet')
            if new_internet not in valid_tables:
                flash("تیبل انتخابی نامعتبر است", "danger")
            else:
                try:
                    remove_user_mangle(api, client_ip)
                    add_user_mangle(api, client_ip, new_internet)
                    flash(f"اینترنت کاربر {client_ip} تغییر کرد", "success")
                except Exception as e:
                    flash(f"خطا در تغییر اینترنت: {e}", "danger")

        elif 'remove_internet' in request.form:
            try:
                remove_user_mangle(api, client_ip)
                flash(f"اینترنت کاربر {client_ip} حذف شد و به پیش‌فرض برگشت", "success")
            except Exception as e:
                flash(f"خطا در حذف اینترنت: {e}", "danger")

        elif 'change_default' in request.form:
            default_table = request.form.get('default_table')
            if default_table not in valid_tables:
                flash("تیبل پیش‌فرض نامعتبر است", "danger")
            else:
                try:
                    route_res = api.get_resource('/ip/route')
                    routes = route_res.get()
                    updated = False

                    for r in routes:
                        if r.get('dst-address') == '0.0.0.0/0' and r.get('routing-table', 'main') == 'main':
                            route_res.set(id=r['id'], routing_table=default_table)
                            updated = True

                    if updated:
                        flash("اینترنت پیش‌فرض با موفقیت تغییر کرد", "success")
                    else:
                        flash("روت پیش‌فرض پیدا نشد", "danger")
                except Exception as e:
                    flash(f"خطا در تغییر اینترنت پیش‌فرض: {e}", "danger")

        elif 'update_table_interfaces' in request.form:
            try:
                table_interface_map = {}
                for key, value in request.form.items():
                    if key.startswith("interface_for_"):
                        table_id = key.replace("interface_for_", "")
                        table_interface_map[table_id] = value
        
                cleaned_map = {key.replace("interface_for_", ""): val for key, val in table_interface_map.items()}
                settings_data["table_interface_map"] = cleaned_map
                save_settings(settings_data)
                apply_table_routes(api, cleaned_map)
                flash("تنظیمات ارتباط جدول‌ها با اینترفیس‌ها ذخیره شد", "success")
            except Exception as e:
                flash(f"خطا در ذخیره تنظیمات: {e}", "danger")

        return redirect(url_for('admin'))

    interfaces_raw = fetch_interfaces(api)
    interfaces_map = settings_data.get("interfaces", {})
    interfaces = {
        i["name"]: interfaces_map.get(i["name"], i["name"])
        for i in interfaces_raw
    }

    table_interface_map = settings_data.get("table_interface_map", {})

    return render_template(
        'admin.html',
        leases=leases,
        tables=friendly_tables,
        default_route=default_route,
        interfaces=interfaces,
        table_interface_map=table_interface_map
    )

# اجرای اولیه هنگام بوت برنامه
if __name__ == "__main__":
    api = connect_api()
    if api:
        settings_data = load_settings()
        if "table_interface_map" in settings_data:
            apply_table_routes(api, settings_data["table_interface_map"])
        else:
            print("ℹ️ هیچ جدول متصل‌شده‌ای به اینترفیس‌ها یافت نشد.")
    else:
        print("⚠️ عدم موفقیت در اتصال به میکروتیک برای اعمال روت اولیه")

    app.run(host="0.0.0.0", port=5000, debug=True)
