from flask import Flask, request, jsonify
from mikrotik import set_route_for_ip
from config import ADMIN_USER, ADMIN_PASS, DEFAULT_ROUTE, SECRET_KEY
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash
import os

app = Flask(__name__)
auth = HTTPBasicAuth()

# لیست کاربران برای احراز هویت
users = {
    ADMIN_USER: generate_password_hash(ADMIN_PASS)
}

# بررسی صحت رمز عبور
@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

# تغییر مسیر اینترنت برای آی‌پی مشخص
@app.route("/api/route", methods=["POST"])
def change_user_route():
    data = request.get_json()
    user_ip = request.remote_addr
    internet = data.get("internet")

    if internet not in ["irancell", "hamrahaval", "adsl", "anten"]:
        return jsonify({"error": "Invalid choice"}), 400

    success = set_route_for_ip(user_ip, internet)
    return jsonify({"status": "ok" if success else "fail"})

# تغییر مسیر پیش‌فرض
@app.route("/api/admin/default", methods=["POST"])
@auth.login_required
def change_default_route():
    data = request.get_json()
    default = data.get("default")

    if default in ["irancell", "hamrahaval", "adsl", "anten"]:
        os.environ["DEFAULT_ROUTE"] = default
        return jsonify({"default": default})
    return jsonify({"error": "Invalid route"}), 400
