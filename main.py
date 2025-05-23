from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from mikrotik_api import connect_api, load_settings, save_settings, fetch_routing_tables, fetch_interfaces, add_user_mangle, remove_user_mangle, get_dhcp_leases, apply_table_routes, get_interface_gateways
import ipaddress

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # برای فلش کردن پیام‌ها

settings = load_settings()

@app.route('/')
def index():
    api = connect_api()
    if not api:
        flash("❌ اتصال به میکروتیک برقرار نشد.", "danger")
        return render_template('index.html', routing_tables=[], interfaces=[], settings=settings)

    routing_tables = fetch_routing_tables(api)
    interfaces = fetch_interfaces(api)

    return render_template('index.html', routing_tables=routing_tables, interfaces=interfaces, settings=settings)

@app.route('/update_mangle', methods=['POST'])
def update_mangle():
    api = connect_api()
    if not api:
        return jsonify({"error": "ارتباط با میکروتیک برقرار نشد."}), 500

    user_ip = request.form.get('user_ip')
    routing_mark = request.form.get('routing_mark')

    # اعتبارسنجی IP
    try:
        ipaddress.ip_address(user_ip)
    except ValueError:
        return jsonify({"error": "آدرس IP نامعتبر است."}), 400

    if not routing_mark:
        return jsonify({"error": "مارک روت باید مشخص شود."}), 400

    try:
        remove_user_mangle(api, user_ip)
        add_user_mangle(api, user_ip, routing_mark)

        # ذخیره در تنظیمات محلی
        settings['routes'][user_ip] = routing_mark
        save_settings(settings)

        return jsonify({"success": "قانون منگل با موفقیت بروزرسانی شد."})
    except Exception as e:
        return jsonify({"error": f"خطا در اعمال قانون: {e}"}), 500

@app.route('/settings', methods=['GET', 'POST'])
def configure_settings():
    global settings

    api = connect_api()
    if not api:
        flash("❌ اتصال به میکروتیک برقرار نشد.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        # دریافت mapping جدول به اینترفیس از فرم
        table_interface_map = {}
        for key, value in request.form.items():
            if key.startswith("table_"):
                table_name = key.split("table_")[1]
                table_interface_map[table_name] = value

        settings['table_interface_map'] = table_interface_map
        save_settings(settings)

        # اعمال روت‌های جدول به اینترفیس‌ها
        apply_table_routes(api, table_interface_map)

        flash("تنظیمات با موفقیت ذخیره و اعمال شد.", "success")
        return redirect(url_for('index'))

    # GET request: نمایش صفحه تنظیمات
    routing_tables = fetch_routing_tables(api)
    interfaces = fetch_interfaces(api)

    return render_template('settings.html', routing_tables=routing_tables, interfaces=interfaces, settings=settings)

@app.route('/dhcp_leases')
def show_dhcp_leases():
    api = connect_api()
    if not api:
        return jsonify({"error": "ارتباط با میکروتیک برقرار نشد."}), 500
    leases = get_dhcp_leases(api)
    return jsonify(leases)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
