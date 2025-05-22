# backend/routes/auth.py
import os
from flask import Blueprint, render_template, request, redirect, url_for, session, flash

auth_bp = Blueprint("auth", __name__)

WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")


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


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
