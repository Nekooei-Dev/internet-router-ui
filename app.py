import os
from flask import Flask, render_template, request, redirect, session
from dotenv import load_dotenv
from ipaddress import ip_network, ip_address
from routeros_api import RouterOsApiPool

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secret')

# ENV config
API_HOST = os.getenv('API_HOST', '172.30.30.254')
API_USER = os.getenv('API_USER', 'API')
API_PASS = os.getenv('API_PASS', 'API')
API_PORT = int(os.getenv('API_PORT', 8728))  # پورت API معمول میکروتیک
USE_SSL = os.getenv('API_USE_SSL', 'false').lower() == 'true'

WEB_USER_PASSWORD = os.getenv('WEB_USER_PASSWORD', '123456')
WEB_ADMIN_PASSWORD = os.getenv('WEB_ADMIN_PASSWORD', '123456789')
ALLOWED_NETWORKS = os.getenv('ALLOWED_NETWORKS', '127.0.0.1').split(',')

DEFAULT_ROUTING_MARK = "To-IranCell"

INTERFACE_MARKS = {
    "1": "To-IranCell",
    "2": "To-HamrahAval",
    "3": "To-ADSL",
    "4": "To-Anten"
}

def allowed_ip(ip):
    for net in ALLOWED_NETWORKS:
        if '-' in net:
            start, end = net.split('-')
            if ip_address(start) <= ip_address(ip) <= ip_address(end):
                return True
        else:
            if ip_address(ip) in ip_network(net):
                return True
    return False

def mikrotik_connect():
    pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, port=API_PORT, use_ssl=USE_SSL)
    return pool.get_api()

@app.route('/')
def index():
    if 'user_type' in session:
        return redirect('/admin' if session['user_type'] == 'admin' else '/change-internet')
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    password = request.form.get('password')
    if password == WEB_ADMIN_PASSWORD:
        session['user_type'] = 'admin'
        return redirect('/admin')
    elif password == WEB_USER_PASSWORD:
        session['user_type'] = 'user'
        return redirect('/change-internet')
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/change-internet', methods=['GET', 'POST'])
def change_internet():
    if 'user_type' not in session or session['user_type'] != 'user':
        return redirect('/')
    
    user_ip = request.remote_addr
    if not allowed_ip(user_ip):
        return "IP not allowed"

    if request.method == 'POST':
        selected_interface = request.form.get('interface')
        mark = INTERFACE_MARKS.get(selected_interface, DEFAULT_ROUTING_MARK)
        try:
            api = mikrotik_connect()
            firewall = api.get_resource('/ip/firewall/mangle')
            rules = firewall.get()
            for rule in rules:
                if 'src-address' in rule and rule['src-address'] == user_ip:
                    firewall.update(id=rule['id'], new_routing_mark=mark)
                    break
            else:
                firewall.add(chain="prerouting", action="mark-routing", new_routing_mark=mark,
                             passthrough="yes", src_address=user_ip)
        except Exception as e:
            return f"Error: {e}"
        return redirect('/change-internet')

    return render_template('change_internet.html', interfaces=INTERFACE_MARKS)

@app.route('/admin')
def admin_panel():
    if 'user_type' not in session or session['user_type'] != 'admin':
        return redirect('/')
    return render_template('admin.html')

@app.route('/user-status')
def user_status():
    if 'user_type' not in session:
        return redirect('/')
    user_ip = request.remote_addr
    if not allowed_ip(user_ip):
        return "IP not allowed"
    try:
        api = mikrotik_connect()
        firewall = api.get_resource('/ip/firewall/mangle')
        rules = firewall.get()
        for rule in rules:
            if 'src-address' in rule and rule['src-address'] == user_ip:
                return render_template('user_status.html', rule=rule)
    except Exception as e:
        return f"Error: {e}"
    return "No rule found"

@app.route('/check-api')
def check_api():
    try:
        api = mikrotik_connect()
        identity = api.get_resource('/system/identity').get()
        return f"Connected to MikroTik: {identity[0]['name']}"
    except Exception as e:
        return f"Error connecting to MikroTik API: {str(e)}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
