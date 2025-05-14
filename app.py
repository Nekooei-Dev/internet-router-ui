from flask import Flask, request, redirect, render_template, url_for, session
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")

# متغیرهای محیطی
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin123")
default_route = os.environ.get("DEFAULT_ROUTE", "irancell")

# مسیرها
routes = {
    "irancell": "to-irancell",
    "hamrahaval": "to-hamrahaval",
    "adsl": "to-adsl",
    "anten": "to-anten"
}

# تابع تنظیم روت (در آینده واقعی میشه با API میکروتیک)
def set_routing(ip, mark):
    print(f"[SET ROUTE] {ip} → {mark}")

@app.route("/", methods=["GET", "POST"])
def index():
    ip = request.remote_addr
    if request.method == "POST":
        choice = request.form["route"]
        set_routing(ip, routes[choice])
        return render_template("index.html", message=f"✅ اینترنت شما به {choice} تغییر یافت", ip=ip)

    set_routing(ip, routes[default_route])
    return render_template("index.html", message=f"🌐 اینترنت پیش‌فرض ({default_route}) فعال است", ip=ip)

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

    global default_route
    message = None

    if request.method == "POST":
        default_route = request.form["default_route"]
        message = f"✅ اینترنت پیش‌فرض به {default_route} تغییر یافت"

    return render_template("admin.html", message=message, current_default=default_route)

@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect("/")

if __name__ == "__main__":
    port = int(os.environ.get("APP_PORT", 8080))
    app.run(host="0.0.0.0", port=port)
