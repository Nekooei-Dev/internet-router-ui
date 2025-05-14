from flask import Flask, request, redirect, render_template, url_for, session
import os
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")

# متغیرهای محیطی
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")
DEFAULT_ROUTE = os.environ.get("DEFAULT_ROUTE", "irancell")
MIKROTIK_URL = os.environ.get("MIKROTIK_URL", "http://192.168.88.1/api")
MIKROTIK_USER = os.environ.get("MIKROTIK_USER", "admin")
MIKROTIK_PASS = os.environ.get("MIKROTIK_PASS", "adminpass")

# مسیرها
routes = {
    "irancell": "to-irancell",
    "hamrahaval": "to-hamrahaval",
    "adsl": "to-adsl",
    "anten": "to-anten"
}

# تابع برای تنظیم روت در MikroTik
def set_routing(ip, mark):
    # اتصال به MikroTik API برای تنظیم روت
    url = f"{MIKROTIK_URL}/routeros"
    auth = (MIKROTIK_USER, MIKROTIK_PASS)
    command = f"/routing table add name={mark} disabled=no"
    
    # ارسال دستور برای تنظیم روت
    response = requests.post(url, data={"command": command}, auth=auth)
    if response.status_code == 200:
        print(f"Route for {ip} set to {mark}")
    else:
        print(f"Failed to set route for {ip}")

@app.route("/", methods=["GET", "POST"])
def index():
    ip = request.remote_addr  # IP کاربر
    if request.method == "POST":
        choice = request.form["route"]
        set_routing(ip, routes[choice])
        return render_template("index.html", message=f"✅ اینترنت شما به {choice} تغییر یافت", ip=ip)
    
    # پیش‌فرض
    set_routing(ip, routes[DEFAULT_ROUTE])
    return render_template("index.html", message=f"🌐 اینترنت پیش‌فرض ({DEFAULT_ROUTE}) فعال است", ip=ip)

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pw = request.form["password"]
        if user == ADMIN_USER and pw == ADMIN_PASS:
            session["admin"] = True
            return redirect("/admin")
        return render_template("login.html", error="❌ ورود ناموفق")
    return render_template("login.html")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("admin"):
        return redirect("/admin/login")

    global DEFAULT_ROUTE
    message = None

    if request.method == "POST":
        DEFAULT_ROUTE = request.form["default_route"]
        message = f"✅ اینترنت پیش‌فرض به {DEFAULT_ROUTE} تغییر یافت"
    
    # ارسال به HTML برای تغییر پیش‌فرض
    return render_template("admin.html", message=message, current_default=DEFAULT_ROUTE)

@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect("/")

if __name__ == "__main__":
    port = int(os.environ.get("APP_PORT", 80))
    app.run(host="0.0.0.0", port=port)
