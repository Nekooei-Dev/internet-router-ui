import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from routeros_api import RouterOsApiPool, ApiException
from ipaddress import ip_network, ip_address

app = Flask(__name__)

# تنظیمات محیطی از میکروتیک یا پیش فرض
app.secret_key = os.environ.get("SECRET_KEY", "9f7e2c45b6a14d9a8e4d31f0c5b2a7e1")
API_HOST = os.environ.get("API_HOST", "172.30.30.254")
API_USER = os.environ.get("API_USER", "API")
API_PASS = os.environ.get("API_PASS", "API")
API_PORT = int(os.environ.get("API_PORT", 8728))
WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")
ALLOWED_NETWORKS = [net.strip() for net in os.environ.get(
    "ALLOWED_NETWORKS",
    "172.30.30.0/24,172.32.30.10-172.32.30.40,192.168.1.10"
).split(",")]

# بررسی اجازه دسترسی آیپی
def ip_allowed(ip_str):
    ip = ip_address(ip_str)
    for net in ALLOWED_NETWORKS:
        if "-" in net:
            start_ip, end_ip = net.split("-")
            if ip_address(start_ip) <= ip <= ip_address(end_ip):
                return True
        else:
            if ip in ip_network(net, strict=False):
                return True
    return False

# اتصال به API میکروتیک
def get_api():
    try:
        api_pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, port=API_PORT, plaintext_login=True)
        api = api_pool.get_api()
        return api, api_pool
    except ApiException as e:
        print(f"API connection error: {e}")
        return None, None

# لاگین: مشخص کردن نقش (ادمین یا کاربر)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == WEB_ADMIN_PASSWORD:
            session["role"] = "admin"
            return redirect(url_for("admin"))
        elif password == WEB_USER_PASSWORD:
            session["role"] = "user"
            return redirect(url_for("user"))
        else:
            flash("رمز اشتباه است.", "danger")
            return render_template("login.html")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# صفحه اصلی (نمای کلی)
@app.route("/")
def index():
    if "role" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", role=session["role"])

# صفحه درباره
@app.route("/about")
def about():
    if "role" not in session:
        return redirect(url_for("login"))
    return render_template("about.html")

# صفحه کاربر عادی: نمایش و تغییر اینترنت خودش
@app.route("/user", methods=["GET", "POST"])
def user():
    if session.get("role") != "user":
        return redirect(url_for("login"))

    api, api_pool = get_api()
    if not api:
        return render_template("error.html", message="ارتباط با میکروتیک برقرار نشد.")
    
    # گرفتن IP کاربر از request (از ip واقعی یا هدر X-Forwarded-For)
    user_ip = request.remote_addr
    # اگر پشت پراکسی هست
    if "X-Forwarded-For" in request.headers:
        user_ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()

    if not ip_allowed(user_ip):
        api_pool.disconnect()
        return render_template("error.html", message="شما اجازه دسترسی ندارید.")

    # گرفتن لیست DHCP Lease ها برای پیدا کردن اینترنتم کاربر
    leases = api.get_resource("/ip/dhcp-server/lease").get()
    user_lease = None
    for lease in leases:
        if lease.get("address") == user_ip:
            user_lease = lease
            break

    # گرفتن لیست روت تیبل‌ها (اینترنت‌ها)
    routing_tables = api.get_resource("/ip/route").get()
    # ساخت لیست تیبل‌های متفاوت (فقط نام تیبل‌های روت دیفالت که ما تعریف کردیم)
    # برای اینجا فقط به تیبل های اصلی میکروتیک نگاه می‌کنیم
    tables = []
    for route in routing_tables:
        if "routing-table" in route and route["routing-table"] not in tables:
            tables.append(route["routing-table"])

    # فقط تیبل‌های معتبر رو نگه دار (ترجیحا)
    tables = list(set(tables))

    if request.method == "POST":
        new_table = request.form.get("internet_table", None)
        if new_table and new_table in tables:
            # حذف روت های فعلی کاربر و ست کردن جدید
            try:
                # حذف روت اختصاصی برای IP کاربر
                routes = api.get_resource("/ip/route")
                # ابتدا همه روت های مخصوص IP کاربر رو حذف می‌کنیم
                for r in routes.get():
                    if r.get("dst-address") == user_ip + "/32":
                        routes.remove(id=r.get(".id"))
                # حالا روت جدید با جدول مشخص شده می‌سازیم
                routes.add(
                    dst_address=user_ip + "/32",
                    gateway="0.0.0.0",  # فرضا مقدار گییت وی دیفالت نیست، باید بررسی شود
                    routing_table=new_table,
                    distance=1
                )
                flash("اینترنت شما با موفقیت تغییر کرد.", "success")
            except Exception as e:
                flash(f"خطا در تغییر اینترنت: {e}", "danger")
        else:
            flash("اینترنت انتخاب شده معتبر نیست.", "warning")

    api_pool.disconnect()
    return render_template("user.html", user_ip=user_ip, user_lease=user_lease, tables=tables)

# صفحه مدیریت: لیست کاربران، تغییر اینترنت، حذف و تنظیم اینترنت دیفالت
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if session.get("role") != "admin":
        return redirect(url_for("login"))

    api, api_pool = get_api()
    if not api:
        return render_template("error.html", message="ارتباط با میکروتیک برقرار نشد.")

    # لیست DHCP Lease کاربران
    leases = api.get_resource("/ip/dhcp-server/lease").get()

    # لیست روت تیبل‌های موجود
    routing_tables = api.get_resource("/ip/route").get()
    tables = []
    for route in routing_tables:
        if "routing-table" in route and route["routing-table"] not in tables:
            tables.append(route["routing-table"])
    tables = list(set(tables))

    # دریافت روت دیفالت فعلی از تنظیمات (مثلا روتی که دارای distance=1 و dst-address=0.0.0.0/0 هست)
    default_route = None
    routes_resource = api.get_resource("/ip/route")
    for r in routes_resource.get():
        if r.get("dst-address") == "0.0.0.0/0" and r.get("distance") == "1":
            default_route = r
            break

    if request.method == "POST":
        # حذف اینترنت کاربر
        if "remove_internet" in request.form:
            client_ip = request.form.get("client_ip")
            if client_ip:
                # حذف روت مربوط به IP کاربر
                routes = api.get_resource("/ip/route")
                removed = False
                for r in routes.get():
                    if r.get("dst-address") == client_ip + "/32":
                        routes.remove(id=r.get(".id"))
                        removed = True
                flash("اینترنت کاربر حذف شد." if removed else "اینترنتی برای کاربر یافت نشد.", "info")

        # تغییر اینترنت کاربر
        if "change_internet" in request.form:
            client_ip = request.form.get("client_ip")
            new_table = request.form.get("new_internet")
            if client_ip and new_table:
                routes = api.get_resource("/ip/route")
                # حذف روت قبلی کاربر
                for r in routes.get():
                    if r.get("dst-address") == client_ip + "/32":
                        routes.remove(id=r.get(".id"))
                # افزودن روت جدید
                try:
                    routes.add(
                        dst_address=client_ip + "/32",
                        gateway="0.0.0.0",
                        routing_table=new_table,
                        distance=1
                    )
                    flash("اینترنت کاربر تغییر یافت.", "success")
                except Exception as e:
                    flash(f"خطا در تغییر اینترنت: {e}", "danger")

        # تغییر روت دیفالت
        if "change_default" in request.form:
            new_default_table = request.form.get("default_table")
            if new_default_table:
                # حذف روت دیفالت فعلی
                if default_route:
                    try:
                        routes_resource.remove(id=default_route.get(".id"))
                    except Exception as e:
                        flash(f"خطا در حذف روت دیفالت: {e}", "danger")
                # اضافه کردن روت دیفالت جدید
                try:
                    routes_resource.add(
                        dst_address="0.0.0.0/0",
                        gateway="0.0.0.0",
                        routing_table=new_default_table,
                        distance=1
                    )
                    flash("اینترنت دیفالت تغییر یافت.", "success")
                except Exception as e:
                    flash(f"خطا در تغییر اینترنت دیفالت: {e}", "danger")

    api_pool.disconnect()
    return render_template("admin.html", leases=leases, tables=tables, default_route=default_route)

# صفحه خطا
@app.route("/error")
def error():
    message = request.args.get("message", "خطایی رخ داده است.")
    return render_template("error.html", message=message)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
