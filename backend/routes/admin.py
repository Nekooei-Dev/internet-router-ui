from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from backend.routes.helpers import connect_api, fetch_routing_tables, fetch_interfaces, get_dhcp_leases, remove_user_mangle, add_user_mangle, load_settings, save_settings, apply_table_routes, get_interface_gateways, get_default_route

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
    default_route = get_default_route(api)
    interface_gateways = get_interface_gateways(api)
    interfaces_raw = fetch_interfaces(api)

    # نمایش دوستانه نام‌ها
    interfaces_map = settings_data.get("interfaces", {})
    interfaces = {i["name"]: interfaces_map.get(i["name"], i["name"]) for i in interfaces_raw}
    friendly_tables = [
        {
            "id": tbl["name"],
            "name": settings_data.get("routing_tables", {}).get(tbl["name"], tbl["name"])
        } for tbl in routing_tables
    ]
    table_interface_map = settings_data.get("table_interface_map", {})

    if request.method == 'POST':
        client_ip = request.form.get("client_ip")
        valid_tables = [t["name"] for t in routing_tables]

        if "change_internet" in request.form:
            new_table = request.form.get("new_internet")
            if new_table not in valid_tables:
                flash("تیبل انتخابی نامعتبر است", "danger")
            else:
                try:
                    remove_user_mangle(api, client_ip)
                    add_user_mangle(api, client_ip, new_table)
                    flash(f"اینترنت کاربر {client_ip} تغییر یافت", "success")
                except Exception as e:
                    flash(f"خطا در تغییر اینترنت: {e}", "danger")

        elif "remove_internet" in request.form:
            try:
                remove_user_mangle(api, client_ip)
                flash(f"اینترنت کاربر {client_ip} به حالت پیش‌فرض بازگشت", "success")
            except Exception as e:
                flash(f"خطا در حذف اینترنت: {e}", "danger")

        elif "change_default" in request.form:
            iface = request.form.get("default_table")
            gateways_map = get_interface_gateways(api)
            if iface not in gateways_map:
                flash("برای این اینترفیس گیت‌وی معتبری یافت نشد", "danger")
            else:
                gateway_ip = gateways_map[iface]
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
                    flash("روت پیش‌فرض با موفقیت اعمال شد", "success")
                except Exception as e:
                    flash(f"خطا در تنظیم روت پیش‌فرض: {e}", "danger")

        elif "update_table_interfaces" in request.form:
            try:
                table_interface_map = {}
                for key, value in request.form.items():
                    if key.startswith("interface_for_"):
                        table_id = key.replace("interface_for_", "")
                        table_interface_map[table_id] = value
                settings_data["table_interface_map"] = table_interface_map
                save_settings(settings_data)
                apply_table_routes(api, table_interface_map)
                flash("تنظیمات جدول-اینترفیس ذخیره شد", "success")
            except Exception as e:
                flash(f"خطا در ذخیره تنظیمات: {e}", "danger")

        return redirect(url_for("admin.admin_panel"))

    return render_template(
        "admin.html",
        leases=leases,
        tables=friendly_tables,
        default_route=default_route,
        interfaces=interfaces,
        table_interface_map=table_interface_map,
        interface_gateways=interface_gateways
    )
