from flask import Blueprint, render_template, session, redirect, url_for

common_bp = Blueprint("common", __name__)

@common_bp.route("/dashboard")
def dashboard():
    role = session.get("role")
    if not role:
        return redirect(url_for("auth.login"))
    return render_template("index.html", role=role)

@common_bp.route("/about")
def about():
    return render_template("about.html")

@common_bp.route("/error")
def error():
    return render_template("error.html", message="مشکلی پیش آمده است.")
