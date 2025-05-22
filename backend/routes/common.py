from flask import Blueprint, render_template, session, redirect, url_for

common_bp = Blueprint("common", __name__)

@common_bp.route("/")
def index():
    role = session.get("role")
    if role == "admin":
        return redirect(url_for("admin.admin"))
    elif role == "user":
        return redirect(url_for("user.user"))
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

@common_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))

@common_bp.app_errorhandler(403)
@common_bp.app_errorhandler(404)
@common_bp.app_errorhandler(500)
def error_handler(e):
    return render_template("error.html", message=str(e)), e.code if hasattr(e, 'code') else 500
