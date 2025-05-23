# File: backend/routes/admin.py

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from backend.utils.mikrotik import (
    connect_api, get_dhcp_leases, remove_user_mangle, add_user_mangle,
    get_interface_gateways, fetch_interfaces, fetch_routing_tables,
    get_default_route, apply_table_routes, load_settings, save_settings
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.before_request
def restrict_to_admin():
    if session.get("role") != "admin":
        return redirect(url_for("auth.login"))


@admin_bp.route("/", methods=["GET", "POST"])
def admin_dashboard():
    api = connect_api()
    if not api:
        return render_template("error.html", message="اتصال به میکروتیک برقرار نشد")

    settings = load_settings()
    leases = get_dhcp_leases(api)
    routing_tables = fetch_routing_tables(api)
    default_route = get_default_route(api)
    interface_gateways = get_interface_gateways(api)
    interfaces_raw = fetch_interfaces(api)

    interfaces = {
        i["name"]: settings.get("interfaces", {}).get(i["name"], i["name"])
        for i in interfaces_raw
    }

    table_interface_map = settings.get("table_interface_map", {})
    friendly_tables = [
        {"id": t["name"], "name": settings.get("routing_tables", {}).get(t["name"], t["name"])}
        for t in routing_tables
    ]

    if request.method == "POST":
        client_ip = request.form.get("client_ip")
        valid_tables = [t["name"] for t in routing_tables]

        # تغییر اینترنت کاربر
        if "change_internet" in request.form:
            new_table = request.form.get("new_internet")
            if new_table not in valid_tables:
                flash("جدول انتخابی نامعتبر است", "danger")
            else:
                try:
                    remove_user_mangle(api, client_ip)
                    add_user_mangle(api, client_ip, new_table)
                    flash("اینترنت کاربر تغییر یافت", "success")
                except Exception as e:
                    flash(f"خطا: {e}", "danger")

        # حذف اینترنت کاربر
        elif "remove_internet" in request.form:
            try:
                remove_user_mangle(api, client_ip)
                flash("اینترنت کاربر به حالت پیش‌فرض برگشت", "success")
            except Exception as e:
                flash(f"خطا: {e}", "danger")

        # تغییر روت پیش‌فرض
        elif "change_default" in request.form:
            iface = request.form.get("default_table")
            if iface not in interface_gateways:
                flash("گیت‌وی برای این اینترفیس یافت نشد", "danger")
            else:
                gateway = interface_gateways[iface]
                try:
                    route_res = api.get_resource('/ip/route')
                    for r in route_res.get():
                        if r.get("dst-address") == "0.0.0.0/0" and r.get("routing-table", "main") == "main":
                            route_res.remove(id=r["id"])

                    route_res.add(
                        dst_address="0.0.0.0/0",
                        gateway=gateway,
                        routing_table="main",
                        comment="default-by-admin"
                    )
                    flash("روت پیش‌فرض تنظیم شد", "success")
                except Exception as e:
                    flash(f"خطا: {e}", "danger")

        # ذخیره نگاشت جدول به اینترفیس
        elif "update_table_interfaces" in request.form:
            try:
                new_map = {}
                for key, val in request.form.items():
                    if key.startswith("interface_for_"):
                        table_id = key.replace("interface_for_", "")
                        new_map[table_id] = val
                settings["table_interface_map"] = new_map
                save_settings(settings)
                apply_table_routes(api, new_map)
                flash("نگاشت جدول‌ها ذخیره شد", "success")
            except Exception as e:
                flash(f"خطا: {e}", "danger")

        return redirect(url_for("admin.admin_dashboard"))

    return render_template(
        "admin.html",
        leases=leases,
        tables=friendly_tables,
        default_route=default_route,
        interfaces=interfaces,
        table_interface_map=table_interface_map,
        interface_gateways=interface_gateways
    )


@admin_bp.route("/settings", methods=["GET", "POST"])
def admin_settings():
    api = connect_api()
    if not api:
        return render_template("error.html", message="عدم اتصال به میکروتیک")

    settings = load_settings()
    interfaces = fetch_interfaces(api)
    routing_tables = fetch_routing_tables(api)

    if request.method == "POST":
        new_ifaces = {}
        new_tables = {}

        for iface in interfaces:
            name = iface["name"]
            new_ifaces[name] = request.form.get(f"iface_{name}", "").strip()

        for tbl in routing_tables:
            name = tbl["name"]
            new_tables[name] = request.form.get(f"table_{name}", "").strip()

        settings["interfaces"] = new_ifaces
        settings["routing_tables"] = new_tables
        save_settings(settings)
        flash("تنظیمات ذخیره شد", "success")
        return redirect(url_for("admin.admin_settings"))

    return render_template(
        "settings.html",
        interfaces=interfaces,
        routing_tables=routing_tables,
        settings=settings
    )
