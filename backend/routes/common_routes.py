from flask import Blueprint, render_template, request, redirect, url_for, session, flash
import os

common_bp = Blueprint("common", __name__)

WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")

@common_bp.route("/", methods=["GET"])
def index():
    if not session.get("logged_in"):
        return redirect(url_for("common.login"))
    return render_template("index.html", role=session.get("role"))

@common_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == WEB_ADMIN_PASSWORD:
            session["logged_in"] = True
            session["role"] = "admin"
            return redirect(url_for("admin.admin_panel"))
        elif password == WEB_USER_PASSWORD:
            session["logged_in"] = True
            session["role"] = "user"
            return redirect(url_for("user.user_panel"))
        else:
            flash("رمز وارد شده اشتباه است!", "danger")
            return redirect(url_for("common.login"))
    return render_template("login.html")

@common_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("common.login"))
