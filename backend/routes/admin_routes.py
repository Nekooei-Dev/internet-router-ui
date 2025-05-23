from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from routeros_api import RouterOsApiPool
import os

admin_bp = Blueprint("admin", __name__)

ROUTING_TABLES = {
    "To-IranCell": "ایرانسل",
    "To-HamrahAval": "همراه اول",
    "To-ADSL": "ADSL",
    "To-Anten": "آنتن",
}

def connect_api():
    api_pool = RouterOsApiPool(
        os.environ.get("API_HOST"),
        username=os.environ.get("API_USER"),
        password=os.environ.get("API_PASS"),
        port=int(os.environ.get("API_PORT")),
        plaintext_login=True,
    )
    api = api_pool.get_api()
    return api, api_pool

@admin_bp.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if not session.get("logged_in") or session.get("role") != "admin":
        return redirect(url_for("common.login"))

    api, api_pool = connect_api()

    try:
        # دریافت لیست DHCP Leaseها
        leases = api.get_resource("/ip/dhcp-server/lease").get()

        # دریافت منگل‌ها برای یافتن اینترنت هر IP
        mangle_resource = api.get_resource("/ip/firewall/mangle")
        mangles = mangle_resource.get()
        mangle_map = {m["comment"]: m.get("new-routing-mark", "نامشخص") for m in mangles if "comment" in m}

        # دریافت تنظیمات روت دیفالت (از تنظیمات ip route با distance=1)
        routes = api.get_resource("/ip/route").get()
        default_route = next((r for r in routes if r.get("dst-address") == "0.0.0.0/0" and r.get("distance") == "1"), None)
        default_table = default_route.get("routing-table") if default_route else None

        if request.method == "POST":
            action = request.form.get("action")
            if action == "change_user_internet":
                user_ip = request.form.get("user_ip")
                new_internet = request.form.get("new_internet")
                if user_ip and new_internet in ROUTING_TABLES:
                    # حذف منگل قبلی برای IP
                    prev_mangles = mangle_resource.get(filter={"comment": user_ip})
                    for m in prev_mangles:
                        mangle_resource.remove(id=m[".id"])
                    # اضافه کردن منگل جدید
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
                    # پیدا کردن روت دیفالت و تغییرش
                    if default_route:
                        api.get_resource("/ip/route").set(id=default_route[".id"], **{"routing-table": new_default})
                        flash(f"اینترنت دیفالت به {ROUTING_TABLES[new_default]} تغییر یافت.", "success")
                    else:
                        flash("مسیری برای اینترنت دیفالت پیدا نشد.", "danger")
                else:
                    flash("اینترنت دیفالت نامعتبر است.", "danger")

            # بروز رسانی اطلاعات بعد از تغییرات
            leases = api.get_resource("/ip/dhcp-server/lease").get()
            mangles = mangle_resource.get()
            mangle_map = {m["comment"]: m.get("new-routing-mark", "نامشخص") for m in mangles if "comment" in m}
            routes = api.get_resource("/ip/route").get()
            default_route = next((r for r in routes if r.get("dst-address") == "0.0.0.0/0" and r.get("distance") == "1"), None)
            default_table = default_route.get("routing-table") if default_route else None

    finally:
        api_pool.disconnect()

    # آماده سازی داده‌ها برای رندر
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

