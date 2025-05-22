from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from backend.routes.helpers import (
    get_user_ip, is_allowed_network,
    WEB_ADMIN_PASSWORD, WEB_USER_PASSWORD
)

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/", methods=["GET", "POST"])
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == WEB_ADMIN_PASSWORD:
            session["role"] = "admin"
            return redirect(url_for("common.dashboard"))
        elif password == WEB_USER_PASSWORD:
            user_ip = get_user_ip()
            if not is_allowed_network(user_ip):
                return render_template("error.html", message="آی‌پی شما مجاز نیست")
            session["role"] = "user"
            return redirect(url_for("common.dashboard"))
        else:
            flash("رمز عبور اشتباه است", "danger")

    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
