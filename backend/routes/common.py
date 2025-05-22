from flask import Blueprint, render_template, redirect, url_for, session

common_bp = Blueprint("common", __name__)

# صفحه اصلی داشبورد پس از ورود
@common_bp.route("/")
def index():
    if "role" not in session:
        return redirect(url_for("auth.login"))
    return render_template("index.html", role=session["role"])

# صفحه درباره ما
@common_bp.route("/about")
def about():
    return render_template("about.html")

# صفحه خطاها
@common_bp.route("/error")
def error():
    return render_template("error.html", message="خطایی رخ داده است")

# خروج از حساب کاربری
@common_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
