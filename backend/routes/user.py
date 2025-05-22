from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from backend.routes.helpers import (
    connect_api, get_user_ip, is_allowed_network, fetch_routing_tables,
    get_dhcp_leases, load_settings, remove_user_mangle, add_user_mangle
)

user_bp = Blueprint("user", __name__, url_prefix="/user")


@user_bp.before_request
def restrict_to_user():
    if session.get("role") != "user":
        return redirect(url_for("auth.login"))


@user_bp.route("/", methods=["GET", "POST"], endpoint="index")
def user_dashboard():
    api = connect_api()
    if not api:
        return render_template("error.html", message="ارتباط با میکروتیک برقرار نشد")

    user_ip = get_user_ip()
    if not is_allowed_network(user_ip):
        return render_template("error.html", message="آی‌پی شما مجاز نیست")

    leases = get_dhcp_leases(api)
    lease = next((l for l in leases if l.get("address") == user_ip), None)

    settings = load_settings()
    routing_tables = fetch_routing_tables(api)

    friendly_tables = [
        {
            "id": tbl["name"],
            "name": settings.get("routing_tables", {}).get(tbl["name"], tbl["name"])
        } for tbl in routing_tables if tbl["name"] != "main"
    ]

    if request.method == "POST":
        selected_table = request.form.get("internet_table")
        valid_ids = [t["name"] for t in routing_tables]

        if selected_table not in valid_ids:
            flash("تیبل انتخابی نامعتبر است", "danger")
        else:
            try:
                remove_user_mangle(api, user_ip)
                add_user_mangle(api, user_ip, selected_table)
                flash("اینترنت شما با موفقیت تغییر یافت", "success")
            except Exception as e:
                flash(f"خطا در تغییر اینترنت: {e}", "danger")

    return render_template("user.html", user_ip=user_ip, user_lease=lease, tables=friendly_tables)
