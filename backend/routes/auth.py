# File: backend/routes/auth.py

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
import os

auth_bp = Blueprint("auth", __name__)

# رمز عبور از متغیر محیطی
WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")

        if password == WEB_ADMIN_PASSWORD:
            session["logged_in"] = True
            session["role"] = "admin"
            return redirect(url_for("common.index"))

        elif password == WEB_USER_PASSWORD:
            session["logged_in"] = True
            session["role"] = "user"
            return redirect(url_for("common.index"))

        else:
            flash("رمز عبور اشتباه است", "danger")
            return redirect(url_for("auth.login"))

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("با موفقیت خارج شدید", "info")
    return redirect(url_for("auth.login"))
