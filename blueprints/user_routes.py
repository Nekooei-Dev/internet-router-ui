from flask import Blueprint, render_template, session, redirect, url_for, flash
from utils.router_api import connect_api

user_bp = Blueprint("user", __name__)

def login_required(func):
    def wrapper(*args, **kwargs):
        if not session.get("logged_in") or session.get("role") != "user":
            flash("دسترسی غیرمجاز.", "danger")
            return redirect(url_for("common.login"))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

@user_bp.route("/user")
@login_required
def user_panel():
    api, api_pool = connect_api()
    try:
        leases = api.get_resource("/ip/dhcp-server/lease").get()
        mangle_resource = api.get_resource("/ip/firewall/mangle")
        mangles = mangle_resource.get()
        mangle_map = {m["comment"]: m.get("new-routing-mark", "دیفالت") for m in mangles if "comment" in m}

        # ساده‌ترین حالت: اولین آی‌پی DHCP را کاربر فرض می‌کنیم
        user_ip = None
        if leases:
            user_ip = leases[0].get("address")

        user_internet = mangle_map.get(user_ip, "دیفالت") if user_ip else "نامشخص"
    finally:
        api_pool.disconnect()

    return render_template("user.html", ip=user_ip, internet=user_internet)
