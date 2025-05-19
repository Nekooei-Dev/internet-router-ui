from flask import Flask, render_template, request, redirect, session, abort, url_for
import os
import routeros_api
import ipaddress


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "defaultsecret")

# میکروتیک API
API_HOST = os.environ.get("API_HOST")
API_USER = os.environ.get("API_USER")
API_PASS = os.environ.get("API_PASS")
API_PORT = int(os.environ.get("API_PORT", 8728))

# احراز هویت
WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")

# کنترل دسترسی آی‌پی
ALLOWED_NETWORKS = os.environ.get("ALLOWED_NETWORKS", "").split(",")


def is_ip_allowed(ip):
    for net in ALLOWED_NETWORKS:
        try:
            if '-' in net:
                start, end = net.split('-')
                if ipaddress.IPv4Address(start) <= ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(end):
                    return True
            else:
                if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(net, strict=False):
                    return True
        except Exception as e:
            print(f"[WARNING] IP check error for {net}: {e}")
    return False



@app.before_request
def limit_remote_addr():
    if not is_ip_allowed(request.remote_addr):
        abort(403)


def get_api():
    try:
        pool = routeros_api.RouterOsApiPool(
            host=API_HOST,
            username=API_USER,
            password=API_PASS,
            port=API_PORT,
            plaintext_login=True
        )
        return pool.get_api(), pool
    except Exception as e:
        print(f"[ERROR] اتصال به MikroTik برقرار نشد: {e}")
        return None, None


def is_logged_in():
    return 'logged_in' in session



@app.route('/', methods=['GET'])
def index():
    api, pool = get_api()
    api_ok = bool(api)
    if pool:
        pool.disconnect()
    return render_template('index.html', api_ok=api_ok)



@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        pw = request.form.get('password')
        if pw in [WEB_USER_PASSWORD, WEB_ADMIN_PASSWORD]:
            session['logged_in'] = True
            session['is_admin'] = (pw == WEB_ADMIN_PASSWORD)
            return redirect(url_for('index'))
        else:
            error = 'رمز عبور اشتباه است'
    return render_template('login.html', error=error)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))



@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not is_logged_in() or not session.get('is_admin'):
        return redirect(url_for('login'))

    api, pool = get_api()
    mangle_list = []
    if api:
        try:
            mangle_resource = api.get_resource('/ip/firewall/mangle')
            rules = mangle_resource.get()
            for rule in rules:
                if rule.get('action') == 'mark-routing':
                    mangle_list.append({
                        'id': rule['.id'],
                        'src-address': rule.get('src-address'),
                        'routing-mark': rule.get('new-routing-mark'),
                        'comment': rule.get('comment', '')
                    })
        except Exception as e:
            flash(f'خطا در دریافت لیست قوانین: {e}', 'danger')
        pool.disconnect()
    else:
        flash('اتصال به روتر برقرار نشد.', 'danger')
    return render_template('admin.html', mangle_list=mangle_list)



@app.route('/admin/delete/<rule_id>')
def delete_rule(rule_id):
    if not is_logged_in() or not session.get('is_admin'):
        return redirect(url_for('login'))

    api, pool = get_api()
    if api:
        try:
            mangle_resource = api.get_resource('/ip/firewall/mangle')
            mangle_resource.remove(id=rule_id)
            flash('قانون با موفقیت حذف شد.', 'success')
        except Exception as e:
            flash(f'خطا در حذف: {e}', 'danger')
        pool.disconnect()
    else:
        flash('اتصال به روتر برقرار نشد.', 'danger')
    return redirect(url_for('admin'))



@app.route('/change_internet', methods=['GET', 'POST'])
def change_internet():
    if not is_logged_in():
        return redirect(url_for('login'))

    user_ip = request.remote_addr

    if request.method == 'POST':
        selected_internet = request.form.get('internet')
        comment = f"User changed to {selected_internet}"
        api, pool = get_api()
        if api:
            try:
                mangle_resource = api.get_resource('/ip/firewall/mangle')
                mangle_resource.add(
                    chain='prerouting',
                    src_address=user_ip,
                    action='mark-routing',
                    new_routing_mark=selected_internet,
                    comment=comment
                )
                flash('اینترنت شما با موفقیت تغییر یافت', 'success')
            except Exception as e:
                flash(f'خطا در تغییر اینترنت: {e}', 'danger')
            pool.disconnect()
        else:
            flash('اتصال به روتر برقرار نشد.', 'danger')
        return redirect(url_for('user_status'))

    options = ['To-ADSL', 'To-SIM', 'To-Fiber']
    return render_template('change_internet.html', options=options)



@app.route('/user_status')
def user_status():
    if not is_logged_in():
        return redirect(url_for('login'))

    user_ip = request.remote_addr
    current_internet = 'پیش‌فرض'

    api, pool = get_api()
    if api:
        try:
            mangle_resource = api.get_resource('/ip/firewall/mangle')
            rules = mangle_resource.get()
            for rule in rules:
                if rule.get('src-address') == user_ip and rule.get('action') == 'mark-routing':
                    current_internet = rule.get('new-routing-mark')
        except Exception as e:
            flash(f'خطا در بازیابی وضعیت اینترنت: {e}', 'danger')
        pool.disconnect()
    else:
        flash('اتصال به روتر برقرار نشد.', 'danger')

    return render_template('user_status.html', current_internet=current_internet)



@app.context_processor
def inject_api_status():
    def check_api_connection():
        try:
            api, pool = get_api()
            if api:
                pool.disconnect()
                return True
        except:
            return False
        return False
    return dict(check_api_connection=check_api_connection)



@app.route('/about')
def about():
    return render_template('about.html')
