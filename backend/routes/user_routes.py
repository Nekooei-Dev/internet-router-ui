from flask import Blueprint, render_template, request, session, redirect, url_for, flash
import os
from routeros_api import RouterOsApiPool

user_bp = Blueprint("user", __name__)

API_HOST = os.environ.get("API_HOST", "172.30.30.254")
API_USER = os.environ.get("API_USER", "API")
API_PASS = os.environ.get("API_PASS", "API")
API_PORT = int(os.environ.get("API_PORT", 8728))

# جدول های روت میکروتیک که قراره انتخاب بشن (اسم هاشون مطابق میکروتیک)
ROUTING_TABLES = {
    "To-IranCell": "ایرانسل",
    "To-HamrahAval": "همراه اول",
    "To-ADSL": "ADSL",
    "To-Anten": "آنتن",
}

def get_user_ip():
    # اگر IP تو سشن نیست از request بگیر
    return session.get("user_ip") or request.remote_addr

def connect_api():
    api_pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, port=API_PORT)
    api = api_pool.get_api()
    return api, api_pool

@user_bp.route("/user", methods=["GET", "POST"])
def user_panel():
    if not session.get("logged_in") or session.get("role") != "user":
        return redirect(url_for("common.login"))

    user_ip = get_user_ip()

    api, api_pool = connect_api()
    try:
        # 1. گرفتن لیست DHCP Lease ها و پیدا کردن اینترنت فعلی کاربر با IP
        leases = api.get_resource("/ip/dhcp-server/lease").get()
        user_lease = next((lease for lease in leases if lease.get("address") == user_ip), None)
        if not user_lease:
            flash("IP کاربر در DHCP Lease یافت نشد.", "warning")
            current_internet = "نامشخص"
        else:
            # فرض کنیم مارک (mark) اینترنت کاربر تو فیلد comment یا به طریقی ذخیره شده
            current_internet = user_lease.get("comment", "نامشخص")

        if request.method == "POST":
            selected_internet = request.form.get("internet")
            if selected_internet not in ROUTING_TABLES.keys():
                flash("اینترنت انتخاب شده نامعتبر است.", "danger")
            else:
                # اینجا باید منگل (mangle) و روت رو به روز کنیم
                # مثلا حذف مارک قبلی و اضافه مارک جدید بر اساس IP کاربر
                # ساده ترین روش: حذف مارک قبلی و اضافه مارک جدید به IP کاربر
                # فقط نمونه هست، باید با دقت API میکروتیک را تنظیم کرد

                # حذف منگل قبلی
                mangle_resource = api.get_resource("/ip/firewall/mangle")
                prev_mangles = mangle_resource.get(filter={"comment": user_ip})
                for m in prev_mangles:
                    mangle_resource.remove(id=m[".id"])

                # اضافه کردن منگل جدید
                mangle_resource.add(chain="prerouting", action="mark-routing", new_routing_mark=selected_internet,
                                    src_address=user_ip, comment=user_ip)

                flash(f"اینترنت شما به {ROUTING_TABLES[selected_internet]} تغییر یافت.", "success")

    finally:
        api_pool.disconnect()

    return render_template("user.html", current_internet=current_internet, routing_tables=ROUTING_TABLES)

