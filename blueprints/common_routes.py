from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from config import Config

common_bp = Blueprint("common", __name__)

@common_bp.route("/", methods=["GET"])
def index():
    if not session.get("logged_in"):
        return redirect(url_for("common.login"))
    return render_template("index.html")

@common_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == Config.WEB_ADMIN_PASSWORD:
            session["logged_in"] = True
            session["role"] = "admin"
            flash("ورود مدیر موفقیت‌آمیز بود.", "success")
            return redirect(url_for("admin.admin_panel"))
        elif password == Config.WEB_USER_PASSWORD:
            session["logged_in"] = True
            session["role"] = "user"
            flash("ورود کاربر موفقیت‌آمیز بود.", "success")
            return redirect(url_for("user.user_panel"))
        else:
            flash("رمز عبور اشتباه است.", "danger")
    return render_template("login.html")

@common_bp.route("/logout")
def logout():
    session.clear()
    flash("خروج از سیستم انجام شد.", "info")
    return redirect(url_for("common.login"))

@common_bp.app_errorhandler(404)
def page_not_found(e):
    return render_template("error.html", error_message="صفحه مورد نظر یافت نشد."), 404
