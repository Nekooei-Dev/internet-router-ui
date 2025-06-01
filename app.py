import os
import json
import ipaddress
from flask import Flask, request, session, render_template, redirect, url_for, flash
from routeros_api import RouterOsApiPool, exceptions
from functools import wraps
from contextlib import contextmanager


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "9f7e2c45b6a14d9a8e4d31f0c5b2a7e1")

API_HOST = os.environ.get("API_HOST", "172.32.40.1")
API_USER = os.environ.get("API_USER", "API")
API_PASS = os.environ.get("API_PASS", "API")
API_PORT = int(os.environ.get("API_PORT", 8728))

WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456")
WEB_SUPERADMIN_PASSWORD = os.environ.get("WEB_SUPERADMIN_PASSWORD", "123456789")

ALLOWED_NETWORKS = [net.strip() for net in os.environ.get(
    "ALLOWED_NETWORKS",
    "172.30.30.0/24 , 172.32.30.10-172.32.30.40 , 192.168.1.10"
).split(",")]

SETTINGS_FILE = "settings.json"


# ========================================================  توابع  ========================================================
# ---------- 📌 0. ذخیره و بارگذاری تنظیمات ----------
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {
                "routing_tables": {},
                "interfaces": {},
                "routes": {},
                "table_interface_map": {}
            }
    else:
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
@contextmanager
def mikrotik_api():
    connection = None
    try:
        connection = RouterOsApiPool(
            API_HOST,
            username=API_USER,
            password=API_PASS,
            port=API_PORT,
            plaintext_login=True
        )
        yield connection.get_api()
    except exceptions.RouterOsApiConnectionError as e:
        print(f"❌ اتصال به میکروتیک ناموفق: {e}")
        yield None
    finally:
        if connection:
            connection.disconnect()



# ---------- 📌 3. دریافت لیست لیست قسمت های مختلف میکروتیک ----------
def fetch_mik_data(api, data_type="all"):
    result = {}

    if data_type in ["routing", "all"]:
        result["routing_tables"] = api.get_resource('/routing/table').get()

    if data_type in ["interfaces", "all"]:
        result["interfaces"] = api.get_resource('/interface/ethernet').get()

    if data_type in ["dhcp_leases", "all"]:
        result["dhcp_leases"] =api.get_resource("/ip/dhcp-server/lease").get()

    return result

# ---------- 📌 4. مدیریت منگل کاربر ----------
def manage_user_mangle(api, user_ip, routing_mark=None, mode="update"):
    try:
        mangle = api.get_resource('/ip/firewall/mangle')
        internal_networks = get_internal_network(API_HOST)

        if mode in ["update", "remove"]:
            rules = mangle.get()
            to_remove = [
                rule['id'] for rule in rules
                if rule.get('comment') in [f"user:{user_ip}", f"EXCEPTION: {user_ip}"]
            ]
            for rule_id in to_remove:
                mangle.remove(id=rule_id)

        if mode in ["update", "add"]:
            if routing_mark is None:
                raise ValueError("پارامتر routing_mark برای حالت add یا update الزامی است.")

            if internal_networks:
                mangle.add(
                    chain="prerouting",
                    src_address=user_ip,
                    dst_address=internal_networks,
                    action="accept",
                    comment=f"EXCEPTION: {user_ip}"
                )

            mangle.add(
                chain="prerouting",
                src_address=user_ip,
                action="mark-routing",
                new_routing_mark=routing_mark,
                passthrough="yes",
                comment=f"user:{user_ip}"
            )

        return True

    except Exception as e:
        print(f"❌ خطا در مدیریت منگل برای {user_ip} | حالت: {mode} | خطا: {e}")
        return False



# ---------- 📌 5. مدیریت IP Route  ----------
def manage_route(api, table_name=None, gateway=None, interface_name=None, interface_gateways=None, comment=None):
    routes = api.get_resource('/ip/route')

    # اگر فقط table_name داده شده باشه، روت پیش‌فرض اون جدول رو برگردون
    if gateway is None and interface_name is None:
        all_routes = routes.get()
        for r in all_routes:
            if r.get('dst-address') == '0.0.0.0/0':
                # اگر جدول خواسته شده مشخص شده، فقط روت مربوط به همون جدول رو بگرد
                if table_name is None or r.get('routing-table') == table_name:
                    return r.get('routing-table', 'main')
        # اگر چیزی پیدا نکرد، پیش‌فرض "main"
        return "main"

    # اگر gateway داده نشده ولی interface_name و interface_gateways هست
    if gateway is None:
        if interface_name and interface_gateways:
            gateway = interface_gateways.get(interface_name, {}).get("gateway")
            if not gateway:
                print(f"❌ گیت‌وی برای اینترفیس '{interface_name}' یافت نشد.")
                return
        else:
            print("❌ هیچ گیت‌وی معتبری برای به‌روزرسانی مسیر داده نشده است.")
            return


    try:
        existing_routes = routes.get()
        for route in existing_routes:
            if route.get('dst-address') == '0.0.0.0/0' and route.get('routing-table') == table_name:
                routes.remove(id=route['id'])
                print(f"🗑️ حذف مسیر پیش‌فرض قبلی (ID: {route['id']}) در جدول {table_name}")

        route_params = {
            "dst-address": "0.0.0.0/0",
            "gateway": gateway,
            "routing-table": table_name,
            "check-gateway": "ping"
        }
        if comment:
            route_params["comment"] = comment

        routes.add(**route_params)
        print(f"✅ مسیر پیش‌فرض جدید با Gateway={gateway} به جدول {table_name} اضافه شد.")

    except Exception as e:
        print(f"❌ خطا در به‌روزرسانی مسیر پیش‌فرض: {e}")



# ---------- 📌 6. دسترسی نقش کاربری ----------
def require_role(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get('role') not in roles:
                flash("دسترسی شما مجاز نیست", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated
    return wrapper




# ---------- 📌 7. بررسی  مجاز بودن IP ورودی ----------
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




# ---------- 📌 13. اعمال روت‌ها از map ----------
def apply_table_routes(api, table_interface_map):
    interface_gateways = get_interface_gateways(api)
    for table, iface in table_interface_map.items():
        gateway_ip = interface_gateways.get(iface, {}).get("gateway")
        if not gateway_ip:
            print(f"⚠️ گیت‌وی برای اینترفیس {iface} یافت نشد. جدول {table} نادیده گرفته شد.")
            continue
        
        # استفاده از تابع آپدیت برای مدیریت هر روت
        manage_route(api, table_name=table, gateway=gateway_ip, comment=f"auto-route:{table}")



# ---------- 📌 14. گرفتن گیت‌وی برای هر اینترفیس ----------
def get_interface_gateways(api, prioritize_dhcp=True):
    gateways = {}

    try:
        routes = api.get_resource("/ip/route").get()
    except Exception as e:
        print(f"❌ خطا در دریافت روت‌ها: {e}")
        routes = []

    try:
        dhcp_clients = api.get_resource("/ip/dhcp-client").get()
    except Exception as e:
        print(f"❌ خطا در دریافت DHCP کلاینت‌ها: {e}")
        dhcp_clients = []

    for r in routes:
        iface = r.get("interface")
        gw = r.get("gateway")
        if iface and gw:
            gateways[iface] = {"gateway": gw, "source": "route"}

    if prioritize_dhcp:
        for client in dhcp_clients:
            iface = client.get("interface")
            gw = client.get("gateway")
            status = client.get("status")
            if iface and gw and status == "bound":
                gateways[iface] = {"gateway": gw, "source": "dhcp"}

    return gateways



# ---------- 📌 15. گرفتن لیست کاربران با اینترنت انتخاب‌شده ----------
def get_custom_routed_users(api):
    try:
        mangle_rules = api.get_resource("/ip/firewall/mangle").get()
        users = []
        for rule in mangle_rules:
            comment = rule.get("comment", "")
            if comment.startswith("user:") and rule.get("new-routing-mark"):
                ip = comment.replace("user:", "")
                users.append({
                    "ip": ip,
                    "routing_mark": rule.get("new-routing-mark")
                })
        return users
    except Exception as e:
        print(f"❌ خطا در دریافت لیست کاربران دارای اینترنت اختصاصی: {e}")
        return []



# ---------- 📌 16. گرفتن اطلاعات لیست DHCP با IP آنها ----------
def get_dhcp_info(api):
    try:
        dhcp_servers = api.get_resource("/ip/dhcp-server").get()
        dhcp_networks = api.get_resource("/ip/dhcp-server/network").get()

        dhcp_info = []
        for server in dhcp_servers:
            name = server.get("name")
            interface = server.get("interface")
            network = next((net.get("address") for net in dhcp_networks if net.get("server") == name), None)

            if interface and network:
                dhcp_info.append({
                    "interface": interface,
                    "network": network
                })

        return dhcp_info

    except Exception as e:
        print(f"❌ خطا در دریافت اطلاعات DHCP: {e}")
        return []


# ---------- 📌 17. گرفتن اطلاعات همه کلاینت ها ----------
def get_all_clients(api):
    leases = fetch_mik_data(api, "dhcp_leases").get("dhcp_leases", [])
    dhcp_info_list = get_dhcp_info(api)

    for dhcp in dhcp_info_list:
        scanned = scan_ip_range(api, interface_name=dhcp["interface"], address_range=dhcp["network"])
        existing_ips = {lease.get("address") for lease in leases}

        for entry in scanned:
            if entry.get("address") not in existing_ips:
                leases.append({
                    "address": entry.get("address"),
                    "mac-address": entry.get("mac-address", "---"),
                    "host-name": entry.get("host-name", "---")
                })

    return leases



# ---------- 📌 18. گرفتن مسیر دهی کاربران ----------
def get_user_routing_status(api):
    leases = get_all_clients(api)
    routed_users = get_custom_routed_users(api)
    routed_ip_map = {u['ip']: u['routing_mark'] for u in routed_users}

    settings_data = load_settings()
    restricted_ips = settings_data.get("blocked_ips", [])
    user_labels = settings_data.get("user_labels", {})

    user_status_list = []
    for lease in leases:
        ip = lease.get("address")
        mac = lease.get("mac-address", "---")
        host = lease.get("host-name", "---")
        is_restricted = ip in restricted_ips
        routing_mark = routed_ip_map.get(ip)

        user_status_list.append({
            "ip": ip,
            "mac": mac,
            "host": host,
            "routing_mark": routing_mark or "main",
            "restricted": is_restricted,
            "label": user_labels.get(ip, "")
        })

    return user_status_list
    

# ---------- 📌 19. گرفتن رنج شبکه داخلی ----------
def get_internal_network(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
        else:
            net = ipaddress.ip_network(f"{ip_str}/64", strict=False)
        return str(net)
    except Exception as e:
        print(f"❌ خطا در محاسبه شبکه داخلی از IP: {e}")
        return None






# ========================================================  ساختار صفحات  ========================================================
# ---------- 📌 صفحه اصلی ----------
@app.route("/")
def index():
    return redirect(url_for("login"))



# ---------- 📌 ورود ----------
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
        elif password == WEB_SUPERADMIN_PASSWORD:
            session['role'] = 'superadmin'
            return redirect(url_for('settings'))

        else:
            flash("رمز عبور اشتباه است", "danger")
    return render_template('login.html')



# ---------- 📌 خروج ----------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))



# ---------- 📌 صفحه نام گذاری و تنظیمات اولیه ----------
@app.route("/settings", methods=["GET", "POST"])
@require_role("superadmin")
def settings():
    with mikrotik_api() as api:
        if not api:
            return render_template("error.html", message="عدم اتصال به API میکروتیک")

        settings_data = load_settings()
        mik_data = fetch_mik_data(api, "all")
        interfaces = mik_data.get("interfaces", [])
        routing_tables = mik_data.get("routing_tables", [])

        if request.method == "POST":
            new_interface_names = {}
            for iface in interfaces:
                iface_id = iface.get("name")
                friendly_name = request.form.get(f"iface_{iface_id}", "").strip()
                if friendly_name:
                    new_interface_names[iface_id] = friendly_name

            new_routing_table_names = {}
            for table in routing_tables:
                table_id = table.get("name")
                friendly_name = request.form.get(f"table_{table_id}", "").strip()
                if friendly_name:
                    new_routing_table_names[table_id] = friendly_name

            settings_data["interfaces"] = new_interface_names
            settings_data["routing_tables"] = new_routing_table_names
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
@require_role("user")
def user():
    if 'role' not in session or session['role'] != 'user':
        return redirect(url_for('login'))

    with mikrotik_api() as api:
        if not api:
            return render_template('error.html', message="ارتباط با میکروتیک برقرار نشد")

        user_ip = get_user_ip()
        settings_data = load_settings()
        if user_ip in settings_data.get("blocked_ips", []):
            return render_template("user.html", user_ip=user_ip, blocked=True)
            
        if not is_allowed_network(user_ip):
            return render_template('error.html', message="IP شما مجاز به استفاده از این صفحه نمی باشد")

        try:
            mik_data = fetch_mik_data(api, "all")
            leases = mik_data.get("dhcp_leases", [])
            user_lease = next((lease for lease in leases if lease.get('address') == user_ip), None)

            settings_data = load_settings()
            routing_tables = mik_data.get("routing_tables", [])

            friendly_tables = [
                {
                    "id": tbl["name"],
                    "name": settings_data.get("routing_tables", {}).get(tbl["name"], tbl["name"])
                } for tbl in routing_tables
            ]

            if request.method == 'POST':
                selected_table = request.form.get('internet_table')
                valid_ids = [tbl["name"] for tbl in routing_tables]
                if selected_table not in valid_ids:
                    flash("تیبل انتخابی نامعتبر است", "danger")
                else:
                    manage_user_mangle(api, user_ip, routing_mark=selected_table, mode="update")
                    flash("اینترنت شما با موفقیت تغییر کرد", "success")

            return render_template(
                'user.html',
                user_ip=user_ip,
                user_lease=user_lease,
                tables=friendly_tables
            )
        except Exception as e:
            print(f"❌ خطا در پردازش صفحه کاربر: {e}")
            return render_template('error.html', message="خطا در بارگذاری اطلاعات کاربر")



# ---------- 📌 صفحه ادمین ----------
@app.route('/admin', methods=['GET', 'POST'])
@require_role("admin", "superadmin")
def admin():
    if session.get('role') not in ['admin', 'superadmin']:
        return redirect(url_for('login'))

    with mikrotik_api() as api:
        if not api:
            return render_template('error.html', message="ارتباط با میکروتیک برقرار نشد")

        try:
            mik_data = fetch_mik_data(api, data_type="all")
            leases = get_all_clients(api)
            routing_tables = mik_data.get("routing_tables", [])
            interfaces_raw = mik_data.get("interfaces", [])

            settings_data = load_settings()
            table_interface_map = settings_data.get("table_interface_map", {})
            interface_gateways = get_interface_gateways(api)
            default_route = manage_route(api)

            friendly_tables = [
                {
                    "id": tbl["name"],
                    "name": settings_data.get("routing_tables", {}).get(tbl["name"], tbl["name"])
                } for tbl in routing_tables
            ]

            interfaces_map = settings_data.get("interfaces", {})
            interfaces = {
                i["name"]: interfaces_map.get(i["name"], i["name"])
                for i in interfaces_raw
            }

            if request.method == 'POST':
                client_ip = request.form.get('client_ip')
                valid_tables = [t["name"] for t in routing_tables]

                if 'change_internet' in request.form:
                    new_internet = request.form.get('new_internet')
                    if new_internet not in valid_tables:
                        flash("تیبل انتخابی نامعتبر است", "danger")
                    else:
                        manage_user_mangle(api, client_ip, routing_mark=new_internet, mode="update")
                        flash(f"اینترنت کاربر {client_ip} تغییر کرد", "success")

                elif 'remove_internet' in request.form:
                    manage_user_mangle(api, client_ip, mode="remove")
                    flash(f"اینترنت کاربر {client_ip} حذف شد و به پیش‌فرض برگشت", "success")

                elif 'change_default' in request.form:
                    iface = request.form.get('default_table')
                    if iface not in interface_gateways:
                        flash("برای این اینترفیس گیت‌وی معتبری یافت نشد", "danger")
                        
                elif 'block_ip' in request.form:
                    ip = request.form.get('client_ip')
                    blocked = settings_data.get("blocked_ips", [])
                    if ip not in blocked:
                        blocked.append(ip)
                        settings_data["blocked_ips"] = blocked
                        save_settings(settings_data)
                        flash(f"تغییر اینترنت برای {ip} غیرفعال شد", "warning")
                
                elif 'unblock_ip' in request.form:
                    ip = request.form.get('client_ip')
                    blocked = settings_data.get("blocked_ips", [])
                    if ip in blocked:
                        blocked.remove(ip)
                        settings_data["blocked_ips"] = blocked
                        save_settings(settings_data)
                        flash(f"تغییر اینترنت برای {ip} فعال شد", "success")

                        
                    else:
                        gateway_ip = interface_gateways[iface]['gateway']
                        route_res = api.get_resource('/ip/route')
                        for r in route_res.get():
                            if r.get("dst-address") == "0.0.0.0/0" and r.get("routing-table", "main") == "main":
                                route_res.remove(id=r["id"])

                        route_res.add(
                            dst_address="0.0.0.0/0",
                            gateway=gateway_ip,
                            **{"routing-table": "main"},
                            comment="default-by-admin"
                        )
                        flash("روت پیش‌فرض با موفقیت تنظیم شد", "success")

                elif 'save_label' in request.form:
                    ip = request.form.get('client_ip')
                    label = request.form.get('new_label', '').strip()
                    labels = settings_data.get("user_labels", {})
                
                    if label:
                        labels[ip] = label
                    else:
                        labels.pop(ip, None)
                
                    settings_data["user_labels"] = labels
                    save_settings(settings_data)
                    flash(f"توضیح کاربر {ip} ذخیره شد", "success")

                elif 'update_table_interfaces' in request.form:
                    table_interface_map = {
                        key.replace("interface_for_", ""): value
                        for key, value in request.form.items() if key.startswith("interface_for_")
                    }
                    settings_data["table_interface_map"] = table_interface_map
                    save_settings(settings_data)
                    apply_table_routes(api, table_interface_map)
                    flash("تنظیمات ارتباط جدول‌ها با اینترفیس‌ها ذخیره شد", "success")

                return redirect(url_for('admin'))

            custom_users = get_custom_routed_users(api)
            user_status_list = get_user_routing_status(api)
            return render_template(
                'admin.html',
                leases=leases,
                custom_users=custom_users,
                user_status_list=user_status_list,
                tables=friendly_tables,
                default_route=default_route,
                interfaces=interfaces,
                table_interface_map=table_interface_map,
                interface_gateways=interface_gateways
            )

        except Exception as e:
            print(f"❌ خطا در پردازش صفحه ادمین: {e}")
            return render_template("error.html", message="خطا در بارگذاری اطلاعات پنل ادمین")






if __name__ == "__main__":
    with mikrotik_api() as api:
        if api:
            settings_data = load_settings()
            if "table_interface_map" in settings_data:
                apply_table_routes(api, settings_data["table_interface_map"])
            else:
                print("ℹ️ هیچ جدول متصل‌شده‌ای به اینترفیس‌ها یافت نشد.")
        else:
            print("⚠️ ارتباط اولیه با میکروتیک برقرار نشد. ادامه اجرا بدون اعمال روت‌ها.")

    app.run(host="0.0.0.0", port=int(os.environ.get("WEB_PORT", 5000)), debug=False)
