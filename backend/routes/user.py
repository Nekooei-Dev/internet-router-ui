# File: backend/routes/user.py

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from backend.utils.mikrotik import (
    connect_api, get_user_ip, is_allowed_network,
    get_dhcp_leases, remove_user_mangle, add_user_mangle,
    fetch_routing_tables, load_settings
)

user_bp = Blueprint("user", __name__, url_prefix="/user")


@user_bp.before_request
def restrict_to_user():
    if session.get("role") != "user":
        return redirect(url_for("auth.login"))


@user_bp.route("/", methods=["GET", "POST"])
def user_dashboard():
    api = connect_api()
    if not api:
        return render_template("error.html", message="اتصال به میکروتیک برقرار نشد")

    user_ip = get_user_ip()
    if not is_allowed_network(user_ip):
        return render_template("error.html", message="آی‌پی شما مجاز نیست")

    leases = get_dhcp_leases(api)
    lease = next((l for l in leases if l.get("address") == user_ip), None)

    settings = load_settings()
    routing_tables = fetch_routing_tables(api)

    friendly_tables = [
        {
            "id": t["name"],
            "name": settings.get("routing_tables", {}).get(t["name"], t["name"])
        }
        for t in routing_tables if t["name"] != "main"
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
                flash("اینترنت شما تغییر یافت", "success")
            except Exception as e:
                flash(f"خطا در تغییر اینترنت: {e}", "danger")

    return render_template(
        "user.html",
        user_ip=user_ip,
        user_lease=lease,
        tables=friendly_tables
    )
