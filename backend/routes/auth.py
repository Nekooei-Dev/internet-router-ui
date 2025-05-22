from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import os

auth_bp = Blueprint("auth", __name__)

WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")

# ---------- 📌 نمایش فرم ورود ----------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")

        if password == WEB_ADMIN_PASSWORD:
            session["role"] = "admin"
            return redirect(url_for("common.dashboard"))

        elif password == WEB_USER_PASSWORD:
            session["role"] = "user"
            return redirect(url_for("common.dashboard"))

        else:
            flash("رمز عبور اشتباه است", "danger")

    return render_template("login.html")


# ---------- 📌 خروج ----------
@auth_bp.route("/logout")
def logout():
    session.pop("role", None)
    flash("با موفقیت خارج شدید", "info")
    return redirect(url_for("auth.login"))
