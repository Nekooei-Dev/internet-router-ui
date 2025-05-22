# backend/routes/common.py
from flask import Blueprint, render_template, redirect, url_for, session

common_bp = Blueprint("common", __name__)

@common_bp.route("/")
def index():
    # اگر قبلاً لاگین کرده، به داشبورد بره
    if "role" in session:
        return redirect(url_for("common.dashboard"))
    return redirect(url_for("auth.login"))

@common_bp.route("/dashboard")
def dashboard():
    role = session.get("role")
    if not role:
        return redirect(url_for("auth.login"))

    return render_template("index.html", role=role)

@common_bp.route("/about")
def about():
    return render_template("about.html")
