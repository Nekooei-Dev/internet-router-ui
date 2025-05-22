from flask import Blueprint, render_template, session, redirect, url_for

common_bp = Blueprint("common", __name__)

@common_bp.route("/")
def index():
    if "role" not in session:
        return redirect(url_for("auth.login"))
    return render_template("index.html", role=session["role"])

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
def error_handler(error):
    return render_template("error.html", message="مشکلی در پردازش درخواست پیش آمد."), error.code
