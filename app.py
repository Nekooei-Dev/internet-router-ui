import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from routeros_api import RouterOsApiPool
from routeros_api.exceptions import RouterOsApiCommunicationError, RouterOsApiConnectionError

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "9f7e2c45b6a14d9a8e4d31f0c5b2a7e1")

API_HOST = os.environ.get("API_HOST", "172.30.30.254")
API_USER = os.environ.get("API_USER", "API")
API_PASS = os.environ.get("API_PASS", "API")
API_PORT = int(os.environ.get("API_PORT", 8728))

WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")

ALLOWED_NETWORKS = [net.strip() for net in os.environ.get(
    "ALLOWED_NETWORKS",
    "172.30.30.0/24 , 172.32.30.10-172.32.30.40 , 192.168.1.10"
).split(",")]

# تعریف تیبل های روتینگ (مانگل‌ها)
ROUTING_TABLES = {
    "پیش فرض": "main",
    "همراه اول": "To-HamrahAval",
    "ایرانسل": "To-IranCell",
    "انتن وایرلس": "To-Anten",
    "تلفن فروشگاه": "To-ADSL",
}

# تعریف اینتر فیس ها
interfaces = {
    "ایرانسل": "Ether1 - Irancell SIM Internet",
    "همراه اول": "Ether2 - MCI SIM Internet",
    "تلفن فروشگاه": "Ether3 - TCI ADSL Internet",
    "انتن وایرلس": "Ether4 - Asiatech Wireless Internet",
}

def connect_api():
    try:
        api = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, port=API_PORT, plaintext_login=True)
        return api.get_api()
    except (RouterOsApiCommunicationError, RouterOsApiConnectionError) as e:
        print(f"API Connection Error: {e}")
        return None

def get_dhcp_leases(api):
    try:
        leases = api.get_resource('/ip/dhcp-server/lease').get()
        return leases
    except Exception as e:
        print(f"Error fetching DHCP leases: {e}")
        return []

def get_routes(api):
    try:
        routes = api.get_resource('/ip/route').get()
        return routes
    except Exception as e:
        print(f"Error fetching routes: {e}")
        return []

def get_mangle_rules(api):
    try:
        mangle = api.get_resource('/ip/firewall/mangle').get()
        return mangle
    except Exception as e:
        print(f"Error fetching mangle rules: {e}")
        return []

def get_default_route(api):
    # فرض می‌کنیم default route یک روت با dst-address=0.0.0.0/0 و routing-table=main یا موارد دیگر است
    routes = get_routes(api)
    for r in routes:
        if r.get('dst-address') == '0.0.0.0/0':
            return r
    return None

def is_allowed_network(ip):
    # این تابع می‌تواند با کتابخانه ipaddress برای بررسی IP داخل شبکه استفاده شود.
    import ipaddress
    ip_addr = ipaddress.ip_address(ip)
    for net in ALLOWED_NETWORKS:
        try:
            if "-" in net:
                # محدوده IP مثل 172.32.30.10-172.32.30.40
                start_ip, end_ip = net.split("-")
                if ipaddress.ip_address(start_ip) <= ip_addr <= ipaddress.ip_address(end_ip):
                    return True
            else:
                net_obj = ipaddress.ip_network(net, strict=False)
                if ip_addr in net_obj:
                    return True
        except Exception:
            continue
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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'role' not in session:
        return redirect(url_for('login'))
    role = session['role']
    return render_template('index.html', role=role)

@app.route('/about')
def about():
    if 'role' not in session:
        return redirect(url_for('login'))
    return render_template('about.html')

@app.route('/user', methods=['GET', 'POST'])
def user():
    if 'role' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    api = connect_api()
    if not api:
        return render_template('error.html', message="ارتباط با میکروتیک برقرار نشد")

    user_ip = request.remote_addr
    if not is_allowed_network(user_ip):
        return render_template('error.html', message="آی‌پی شما مجاز نیست")

    leases = get_dhcp_leases(api)
    user_lease = None
    for lease in leases:
        if lease.get('address') == user_ip:
            user_lease = lease
            break

    tables = list(ROUTING_TABLES.values())
    if request.method == 'POST':
        selected_table = request.form.get('internet_table')
        if selected_table not in tables:
            flash("تیبل انتخابی نامعتبر است", "danger")
        else:
            # اینجا منگل روتینگ را به IP کاربر تغییر می‌دهیم
            try:
                # حذف منگل قبلی برای این IP
                mangle_res = api.get_resource('/ip/firewall/mangle')
                rules = mangle_res.get()
                for rule in rules:
                    if rule.get('comment') == f"user:{user_ip}":
                        mangle_res.remove(id=rule['id'])
                # اضافه کردن منگل جدید با انتخاب کاربر
                mangle_res.add(
                    chain='prerouting',
                    src_address=user_ip,
                    action='mark-routing',
                    new_routing_mark=selected_table,
                    comment=f"user:{user_ip}",
                    passthrough='yes'
                )
                flash("اینترنت شما با موفقیت تغییر کرد", "success")
            except Exception as e:
                flash(f"خطا در تغییر اینترنت: {e}", "danger")

    return render_template('user.html', user_ip=user_ip, user_lease=user_lease, tables=tables)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    api = connect_api()
    if not api:
        return render_template('error.html', message="ارتباط با میکروتیک برقرار نشد")

    leases = get_dhcp_leases(api)
    tables = list(ROUTING_TABLES.values())
    default_route = get_default_route(api)

    if request.method == 'POST':
        if 'change_internet' in request.form:
            client_ip = request.form.get('client_ip')
            new_internet = request.form.get('new_internet')
            if new_internet not in tables:
                flash("تیبل انتخابی نامعتبر است", "danger")
            else:
                try:
                    # حذف منگل قبلی برای IP
                    mangle_res = api.get_resource('/ip/firewall/mangle')
                    rules = mangle_res.get()
                    for rule in rules:
                        if rule.get('comment') == f"user:{client_ip}":
                            mangle_res.remove(id=rule['id'])
                    # اضافه کردن منگل جدید
                    mangle_res.add(
                        chain='prerouting',
                        src_address=client_ip,
                        action='mark-routing',
                        new_routing_mark=new_internet,
                        comment=f"user:{client_ip}",
                        passthrough='yes'
                    )
                    flash(f"اینترنت کاربر {client_ip} تغییر کرد", "success")
                except Exception as e:
                    flash(f"خطا در تغییر اینترنت: {e}", "danger")

        elif 'remove_internet' in request.form:
            client_ip = request.form.get('client_ip')
            try:
                mangle_res = api.get_resource('/ip/firewall/mangle')
                rules = mangle_res.get()
                for rule in rules:
                    if rule.get('comment') == f"user:{client_ip}":
                        mangle_res.remove(id=rule['id'])
                flash(f"اینترنت کاربر {client_ip} حذف شد و به پیش‌فرض برگشت", "success")
            except Exception as e:
                flash(f"خطا در حذف اینترنت: {e}", "danger")

        elif 'change_default' in request.form:
            default_table = request.form.get('default_table')
            if default_table not in tables:
                flash("تیبل پیش‌فرض نامعتبر است", "danger")
            else:
                try:
                    # پیدا کردن default route و تغییر routing table آن
                    route_res = api.get_resource('/ip/route')
                    routes = route_res.get()
                    updated = False
                    for r in routes:
                        if r.get('dst-address') == '0.0.0.0/0':
                            route_res.set(id=r['id'], routing_table=default_table)
                            updated = True
                    if updated:
                        flash("اینترنت پیش‌فرض با موفقیت تغییر کرد", "success")
                    else:
                        flash("روت پیش‌فرض پیدا نشد", "danger")
                except Exception as e:
                    flash(f"خطا در تغییر اینترنت پیش‌فرض: {e}", "danger")

        return redirect(url_for('admin'))

    return render_template('admin.html', leases=leases, tables=tables, default_route=default_route)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="صفحه مورد نظر یافت نشد"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html', message="خطای داخلی سرور"), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
