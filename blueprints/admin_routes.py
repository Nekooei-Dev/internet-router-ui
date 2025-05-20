from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from utils.router_api import connect_api

admin_bp = Blueprint("admin", __name__)

ROUTING_TABLES = {
    "To-IranCell": "ایرانسل",
    "To-HamrahAval": "همراه اول",
    "To-ADSL": "ADSL",
    "To-Anten": "آنتن",
}

def admin_required(func):
    def wrapper(*args, **kwargs):
        if not session.get("logged_in") or session.get("role") != "admin":
            flash("دسترسی غیرمجاز.", "danger")
            return redirect(url_for("common.login"))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@admin_bp.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_panel():
    api, api_pool = connect_api()

    try:
        leases = api.get_resource("/ip/dhcp-server/lease").get()
        mangle_resource = api.get_resource("/ip/firewall/mangle")
        mangles = mangle_resource.get()
        mangle_map = {m["comment"]: m.get("new-routing-mark", "دیفالت") for m in mangles if "comment" in m}

        routes = api.get_resource("/ip/route").get()
        default_route = next((r for r in routes if r.get("dst-address") == "0.0.0.0/0" and r.get("distance") == "1"), None)
        default_table = default_route.get("routing-table") if default_route else None

        if request.method == "POST":
            action = request.form.get("action")
            if action == "change_user_internet":
                user_ip = request.form.get("user_ip")
                new_internet = request.form.get("new_internet")
                if user_ip and new_internet in ROUTING_TABLES:
                    prev_mangles = mangle_resource.get(filter={"comment": user_ip})
                    for m in prev_mangles:
                        mangle_resource.remove(id=m[".id"])
                    mangle_resource.add(
                        chain="prerouting",
                        action="mark-routing",
                        new_routing_mark=new_internet,
                        src_address=user_ip,
                        comment=user_ip,
                        passthrough="yes"
                    )
                    flash(f"اینترنت کاربر {user_ip} به {ROUTING_TABLES[new_internet]} تغییر یافت.", "success")
                else:
                    flash("اطلاعات نامعتبر برای تغییر اینترنت کاربر.", "danger")

            elif action == "change_default_internet":
                new_default = request.form.get("default_internet")
                if new_default in ROUTING_TABLES:
                    if default_route:
                        api.get_resource("/ip/route").set(id=default_route[".id"], **{"routing-table": new_default})
                        flash(f"اینترنت دیفالت به {ROUTING_TABLES[new_default]} تغییر یافت.", "success")
                    else:
                        flash("مسیری برای اینترنت دیفالت پیدا نشد.", "danger")
                else:
                    flash("اینترنت دیفالت نامعتبر است.", "danger")

            leases = api.get_resource("/ip/dhcp-server/lease").get()
            mangles = mangle_resource.get()
            mangle_map = {m["comment"]: m.get("new-routing-mark", "دیفالت") for m in mangles if "comment" in m}
            routes = api.get_resource("/ip/route").get()
            default_route = next((r for r in routes if r.get("dst-address") == "0.0.0.0/0" and r.get("distance") == "1"), None)
            default_table = default_route.get("routing-table") if default_route else None

    finally:
        api_pool.disconnect()

    users = []
    for lease in leases:
        ip = lease.get("address")
        users.append({
            "ip": ip,
            "mac": lease.get("mac-address", ""),
            "active": lease.get("active-address", "") or "نامشخص",
            "current_internet": mangle_map.get(ip, "دیفالت"),
        })

    return render_template("admin.html", users=users, routing_tables=ROUTING_TABLES, default_internet=default_table)
