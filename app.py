import os
import logging
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
from routeros_api import RouterOsApiPool, ApiException


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
ALLOWED_NETWORKS = os.environ.get("ALLOWED_NETWORKS", "172.30.30.0/24 , 172.32.30.10-172.32.30.40 , 192.168.1.10").split(",")

logging.basicConfig(level=logging.INFO)

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


def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip


def get_api_connection():
    try:
        connection = RouterOsApiPool(
            API_HOST,
            username=API_USER,
            password=API_PASS,
            port=API_PORT,
            plaintext_login=True,
            use_ssl=False,
            ssl_verify=False
        )
        api = connection.get_api()
        return api, connection
    except ApiException as e:
        logging.error(f"API connection error: {e}")
        return None, None


@app.before_request
def check_ip_allowed():
    ip = get_client_ip()
    if not is_ip_allowed(ip):
        logging.warning(f"Access denied for IP: {ip}")
        abort(403)


@app.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    api, connection = get_api_connection()
    if not api:
        return "Error connecting to MikroTik API", 500
    try:
        mangle_rules = api.get_resource('/ip/firewall/mangle').get()
    except Exception as e:
        logging.error(f"Error fetching mangle rules: {e}")
        mangle_rules = []
    finally:
        connection.disconnect()
    return render_template('index.html', mangle_rules=mangle_rules)



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == WEB_USER_PASSWORD or password == WEB_ADMIN_PASSWORD:
            session['logged_in'] = True
            session['is_admin'] = (password == WEB_ADMIN_PASSWORD)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Password incorrect")
    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/admin')
def admin():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('login'))
    api, connection = get_api_connection()
    if not api:
        return "Error connecting to MikroTik API", 500
    try:
        users = api.get_resource('/ip/hotspot/user').get()
        profiles = api.get_resource('/ip/hotspot/user/profile').get()
    except Exception as e:
        logging.error(f"Error fetching admin data: {e}")
        users, profiles = [], []
    finally:
        connection.disconnect()
    return render_template('admin.html', users=users, profiles=profiles)

@app.route('/change_internet', methods=['POST'])
def change_internet():
    if not session.get('logged_in'):
        return jsonify({"error": "Not authenticated"}), 401
    data = request.json
    user_id = data.get('id')
    action = data.get('action')  # مثلا 'enable' یا 'disable'
    api, connection = get_api_connection()
    if not api:
        return jsonify({"error": "Connection failed"}), 500
    try:
        hotspot_user = api.get_resource('/ip/hotspot/user')
        if action == 'enable':
            hotspot_user.call('enable', **{'numbers': user_id})
        elif action == 'disable':
            hotspot_user.call('disable', **{'numbers': user_id})
        else:
            return jsonify({"error": "Invalid action"}), 400
    except Exception as e:
        logging.error(f"Error changing internet status: {e}")
        return jsonify({"error": "Operation failed"}), 500
    finally:
        connection.disconnect()
    return jsonify({"success": True})

@app.route('/user_status/<user_id>')
def user_status(user_id):
    if not session.get('logged_in'):
        return jsonify({"error": "Not authenticated"}), 401
    api, connection = get_api_connection()
    if not api:
        return jsonify({"error": "Connection failed"}), 500
    try:
        users = api.get_resource('/ip/hotspot/user').get()
        user = next((u for u in users if u['.id'] == user_id), None)
    except Exception as e:
        logging.error(f"Error fetching user status: {e}")
        user = None
    finally:
        connection.disconnect()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)


@app.route('/about')
def about():
    return render_template('about.html')
