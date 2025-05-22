from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from backend.routes.helpers import connect_api, fetch_interfaces, fetch_routing_tables, load_settings, save_settings

settings_bp = Blueprint("settings", __name__)

@settings_bp.route("/settings", methods=["GET", "POST"])
def settings():
    if session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    api = connect_api()
    if not api:
        return render_template("error.html", message="عدم اتصال به میکروتیک")

    interfaces = fetch_interfaces(api)
    routing_tables = fetch_routing_tables(api)
    settings_data = load_settings()

    if request.method == "POST":
        new_interface_names = {}
        for iface in interfaces:
            name = iface["name"]
            friendly = request.form.get(f"iface_{name}", "").strip()
            if friendly:
                new_interface_names[name] = friendly

        new_table_names = {}
        for tbl in routing_tables:
            name = tbl["name"]
            friendly = request.form.get(f"table_{name}", "").strip()
            if friendly:
                new_table_names[name] = friendly

        settings_data["interfaces"] = new_interface_names
        settings_data["routing_tables"] = new_table_names
        save_settings(settings_data)

        flash("تنظیمات ذخیره شد", "success")
        return redirect(url_for("settings.settings"))

    return render_template(
        "settings.html",
        interfaces=interfaces,
        routing_tables=routing_tables,
        settings=settings_data
    )
