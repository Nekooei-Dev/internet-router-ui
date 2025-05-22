from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from backend.routes.helpers import (
    connect_api, fetch_routing_tables, fetch_interfaces,
    load_settings, save_settings
)

settings_bp = Blueprint("settings", __name__)

@settings_bp.route("/settings", methods=["GET", "POST"])
def settings():
    if session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    api = connect_api()
    if not api:
        return render_template("error.html", message="عدم اتصال به میکروتیک")

    settings_data = load_settings()
    interfaces = fetch_interfaces(api)
    routing_tables = fetch_routing_tables(api)

    if request.method == "POST":
        new_interface_names = {}
        for iface in interfaces:
            iface_id = iface.get("name")
            friendly_name = request.form.get(f"iface_{iface_id}", "").strip()
            if friendly_name:
                new_interface_names[iface_id] = friendly_name

        new_routing_names = {}
        for table in routing_tables:
            table_id = table.get("name")
            friendly_name = request.form.get(f"table_{table_id}", "").strip()
            if friendly_name:
                new_routing_names[table_id] = friendly_name

        settings_data["interfaces"] = new_interface_names
        settings_data["routing_tables"] = new_routing_names
        save_settings(settings_data)

        flash("تنظیمات با موفقیت ذخیره شد", "success")
        return redirect(url_for("settings.settings"))

    return render_template(
        "settings.html",
        interfaces=interfaces,
        routing_tables=routing_tables,
        settings=settings_data
    )
