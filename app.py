from flask import Flask, request, session, redirect, send_file
from routeros_api import RouterOsApiPool
import os
import ipaddress

# Flask setup
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'changeme')

# ENV variables
API_HOST = os.getenv('API_HOST', '192.168.88.1')
API_USER = os.getenv('API_USER', 'admin')
API_PASS = os.getenv('API_PASS', '')
WEB_PASSWORD = os.getenv('WEB_PASSWORD', '1234')
WEB_PORT = int(os.getenv('WEB_PORT', 5000))

# ALLOWED_NETWORKS مثل: 192.168.88.0/24,172.30.30.0/24
ALLOWED_NETWORKS = [ipaddress.ip_network(net.strip()) for net in os.getenv("ALLOWED_NETWORKS", "192.168.88.0/24").split(",")]


def is_allowed(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in ALLOWED_NETWORKS)
    except ValueError:
        return False

@app.before_request
def restrict_to_allowed_networks():
    if not is_allowed(request.remote_addr):
        return "دسترسی فقط برای کاربران شبکه داخلی مجاز است", 403


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == WEB_PASSWORD:
            session["authenticated"] = True
            return redirect("/")
        else:
            return "رمز عبور اشتباه است"
    return '''
        <!DOCTYPE html>
        <html lang="fa" dir="rtl">
        <head><meta charset="UTF-8"><title>ورود</title></head>
        <body>
        <form method="post">
            <label>رمز عبور: <input type="password" name="password"></label>
            <input type="submit" value="ورود">
        </form>
        </body>
        </html>
    '''

@app.route("/")
def index():
    if not session.get("authenticated"):
        return redirect("/login")
    return send_file("templates/index.html")


@app.route("/set")
def set_internet():
    if not session.get("authenticated"):
        return "Unauthorized", 401

    inet = request.args.get("inet")
    if not inet or inet not in ["1", "2", "3", "4"]:
        return "Invalid option", 400

    try:
        pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, plaintext_login=True)
        api = pool.get_api()
        route_table = {
            "1": "to-irancell",
            "2": "to-hamrahaval",
            "3": "to-adsl",
            "4": "to-anten"
        }[inet]

        # تنظیم جدول مسیریابی پیش‌فرض
        api.get_resource("/ip/route").call("set", {
            ".id": "*0",  # اولین default route
            "routing-table": route_table
        })

        pool.disconnect()
        return "OK"
    except Exception as e:
        return f"Error: {str(e)}", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=WEB_PORT)
