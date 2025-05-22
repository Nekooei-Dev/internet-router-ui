from flask import Blueprint, render_template, session, redirect, url_for
from backend.routes.helpers import fetch_interfaces, get_interface_gateways, load_settings, connect_api

common_bp = Blueprint("common", __name__)

@common_bp.route("/")
def index():
    if "role" not in session:
        return redirect(url_for("auth.login"))

    role = session["role"]
    return render_template("index.html", role=role)

@common_bp.route("/about")
def about():
    return render_template("about.html")

@common_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))

@common_bp.route("/settings", methods=["GET", "POST"])
def settings_redirect():
    # اگر کسی مستقیم خواست /settings رو بزنه، فقط ادمین‌ها اجازه دارن
    if session.get("role") != "admin":
        return redirect(url_for("auth.login"))
    return redirect(url_for("admin.admin_settings"))
