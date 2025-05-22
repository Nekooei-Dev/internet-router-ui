from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from utils.mikrotik import connect_api, get_user_ip, is_allowed_network, get_dhcp_leases, fetch_routing_tables, remove_user_mangle, add_user_mangle, load_settings

user_bp = Blueprint("user", __name__)

@user_bp.route("/user", methods=["GET", "POST"])
def user_panel():
    if 'role' not in session or session['role'] != 'user':
        return redirect(url_for('auth.login'))

    api = connect_api()
    if not api:
        return render_template('error.html', message="ارتباط با میکروتیک برقرار نشد")

    user_ip = get_user_ip()
    if not is_allowed_network(user_ip):
        return render_template('error.html', message="آی‌پی شما مجاز نیست")

    leases = get_dhcp_leases(api)
    user_lease = next((lease for lease in leases if lease.get('address') == user_ip), None)

    settings_data = load_settings()
    routing_tables = fetch_routing_tables(api)

    friendly_tables = [
        {
            "id": tbl["name"],
            "name": settings_data.get("routing_tables", {}).get(tbl["name"], tbl["name"])
        } for tbl in routing_tables if tbl["name"] != "main"
    ]

    if request.method == 'POST':
        selected_table = request.form.get('internet_table')
        valid_ids = [tbl["name"] for tbl in routing_tables]

        if selected_table not in valid_ids:
            flash("تیبل انتخابی نامعتبر است", "danger")
        else:
            try:
                remove_user_mangle(api, user_ip)
                add_user_mangle(api, user_ip, selected_table)
                flash("اینترنت شما با موفقیت تغییر کرد", "success")
            except Exception as e:
                flash(f"خطا در تغییر اینترنت: {e}", "danger")

    return render_template(
        'user.html',
        user_ip=user_ip,
        user_lease=user_lease,
        tables=friendly_tables
    )
