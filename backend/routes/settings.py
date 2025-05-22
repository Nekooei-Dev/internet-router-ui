from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from utils.mikrotik import connect_api, fetch_interfaces, fetch_routing_tables, load_settings, save_settings

settings_bp = Blueprint("settings", __name__)

@settings_bp.route("/settings", methods=["GET", "POST"])
def settings_panel():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('auth.login'))

    api = connect_api()
    if not api:
        return render_template("error.html", message="عدم اتصال به MikroTik")

    settings_data = load_settings()
    interfaces = fetch_interfaces(api)
    routing_tables = fetch_routing_tables(api)

    if request.method == "POST":
        new_interface_names = {}
        new_routing_names = {}

        for iface in interfaces:
            iface_id = iface.get("name")
            friendly = request.form.get(f"iface_{iface_id}", "").strip()
            if friendly:
                new_interface_names[iface_id] = friendly

        for table in routing_tables:
            table_id = table.get("name")
            friendly = request.form.get(f"table_{table_id}", "").strip()
            if friendly:
                new_routing_names[table_id] = friendly

        settings_data["interfaces"] = new_interface_names
        settings_data["routing_tables"] = new_routing_names
        save_settings(settings_data)
        flash("تنظیمات با موفقیت ذخیره شد", "success")
        return redirect(url_for("settings.settings_panel"))

    return render_template(
        "settings.html",
        interfaces=interfaces,
        routing_tables=routing_tables,
        settings=settings_data
    )
