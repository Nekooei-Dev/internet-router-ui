from flask import Blueprint, render_template, session, redirect, url_for

common_bp = Blueprint("common", __name__)

# ---------- 📌 صفحه اصلی ----------
@common_bp.route("/")
def index():
    return redirect(url_for("auth.login"))

# ---------- 📌 داشبورد بعد از لاگین ----------
@common_bp.route("/dashboard")
def dashboard():
    role = session.get("role")

    if not role:
        return redirect(url_for("auth.login"))

    return render_template("index.html", role=role)

# ---------- 📌 درباره ما ----------
@common_bp.route("/about")
def about():
    return render_template("about.html")
