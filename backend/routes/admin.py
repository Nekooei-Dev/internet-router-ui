from flask import Blueprint, render_template, session, redirect, url_for, request, flash
from backend.utils.api import (
    connect_api, get_dhcp_leases, fetch_routing_tables, fetch_interfaces,
    remove_user_mangle, add_user_mangle, load_settings, save_settings,
    apply_table_routes, get_default_route, get_interface_gateways
)

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if session.get("role") != "admin":
        return redirect(url_for("auth.login"))

    api = connect_api()
    if not api:
        return render_template("error.html", message="ارتباط با میکروتیک برقرار نشد")

    settings_data = load_settings()
    leases = get_dhcp_leases(api)
    routing_tables = fetch_routing_tables(api)
    interfaces_raw = fetch_interfaces(api)
    default_route = get_default_route(api)
    interface_gateways = get_interface_gateways(api)

    interfaces_map = settings_data.get("interfaces", {})
    interfaces = {i["name"]: interfaces_map.get(i["name"], i["name"]) for i in interfaces_raw}

    friendly_tables = [
        {
            "id": tbl["name"],
            "name": settings_data.get("routing_tables", {}).get(tbl["name"], tbl["name"])
        } for tbl in routing_tables if tbl["name"] != "main"
    ]

    if request.method == "POST":
        client_ip = request.form.get("client_ip")
        valid_tables = [t["id"] for t in friendly_tables]

        if "change_internet" in request.form:
            new_internet = request.form.get("new_internet")
            if new_internet not in valid_tables:
                flash("تیبل انتخابی نامعتبر است", "danger")
            else:
                try:
                    remove_user_mangle(api, client_ip)
                    add_user_mangle(api, client_ip, new_internet)
                    flash(f"اینترنت کاربر {client_ip} تغییر کرد", "success")
                except Exception as e:
                    flash(f"خطا در تغییر اینترنت: {e}", "danger")

        elif "remove_internet" in request.form:
            try:
                remove_user_mangle(api, client_ip)
                flash(f"اینترنت کاربر {client_ip} به حالت پیش‌فرض بازگشت", "success")
            except Exception as e:
                flash(f"خطا در بازگشت به پیش‌فرض: {e}", "danger")

        elif "change_default" in request.form:
            iface = request.form.get("default_table")
            gateway_ip = interface_gateways.get(iface)
            if not gateway_ip:
                flash("گیت‌وی معتبر برای این اینترفیس یافت نشد", "danger")
            else:
                try:
                    route_res = api.get_resource("/ip/route")
                    for r in route_res.get():
                        if r.get("dst-address") == "0.0.0.0/0" and r.get("routing-table", "main") == "main":
                            route_res.remove(id=r["id"])

                    route_res.add(
                        dst_address="0.0.0.0/0",
                        gateway=gateway_ip,
                        routing_table="main",
                        comment="default-by-admin"
                    )
                    flash("روت پیش‌فرض تنظیم شد", "success")
                except Exception as e:
                    flash(f"خطا در تغییر روت پیش‌فرض: {e}", "danger")

        elif "update_table_interfaces" in request.form:
            try:
                table_interface_map = {
                    key.replace("interface_for_", ""): val
                    for key, val in request.form.items()
                    if key.startswith("interface_for_")
                }
                settings_data["table_interface_map"] = table_interface_map
                save_settings(settings_data)
                apply_table_routes(api, table_interface_map)
                flash("تنظیمات ارتباط جدول‌ها ذخیره شد", "success")
            except Exception as e:
                flash(f"خطا در ذخیره تنظیمات: {e}", "danger")

        return redirect(url_for("admin.admin_panel"))

    table_interface_map = settings_data.get("table_interface_map", {})

    return render_template(
        "admin.html",
        leases=leases,
        tables=friendly_tables,
        interfaces=interfaces,
        table_interface_map=table_interface_map,
        interface_gateways=interface_gateways,
        default_route=default_route
    )
