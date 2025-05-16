import os
from flask import Flask, render_template, request, redirect, session
import paramiko
from ipaddress import ip_network, ip_address

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secret')

# ENV config
API_HOST = os.getenv('API_HOST', '172.30.30.254')
API_USER = os.getenv('API_USER', 'API')
API_PASS = os.getenv('API_PASS', 'API')
API_PORT = int(os.getenv('API_PORT', 22))
API_USE_SSL = os.getenv('API_USE_SSL', 'false').lower() == 'true'
WEB_PORT = int(os.getenv('WEB_PORT', 5000))

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
        elif '/' in net:
            if ip_address(ip) in ip_network(net, strict=False):
                return True
        else:
            if ip == net:
                return True
    return False


def ssh_command(command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(API_HOST, port=API_PORT, username=API_USER, password=API_PASS, timeout=5)
    stdin, stdout, stderr = ssh.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()
    ssh.close()
    if error:
        raise Exception(error)
    return output


@app.before_request
def check_ip():
    if not allowed_ip(request.remote_addr):
        return "⛔ دسترسی برای IP شما مجاز نیست.", 403


@app.route('/')
def index():
    if not session.get('authenticated'):
        return redirect('/login')
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        pwd = request.form.get('password')
        if pwd == WEB_USER_PASSWORD:
            session['authenticated'] = True
            session['role'] = 'user'
            return redirect('/')
        elif pwd == WEB_ADMIN_PASSWORD:
            session['authenticated'] = True
            session['role'] = 'admin'
            return redirect('/admin')
        else:
            error = "رمز اشتباه است"
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@app.route('/check_api')
def check_api():
    if not session.get('authenticated'):
        return redirect('/login')
    try:
        output = ssh_command('/system identity print')
        return render_template('check_api.html', status="✅ اتصال موفق: " + output)
    except Exception as e:
        return render_template('check_api.html', status=f"❌ خطا: {e}")


@app.route('/user_status')
def user_status():
    if not session.get('authenticated'):
        return redirect('/login')
    ip = request.remote_addr
    try:
        result = ssh_command(f'/ip firewall mangle print where comment="Internet Switcher {ip}"')
        return render_template('user_status.html', routing_mark=result if result else "هیچ منگلی یافت نشد")
    except Exception as e:
        return render_template('user_status.html', routing_mark=f"خطا: {e}")


@app.route('/change_internet', methods=['GET', 'POST'])
def change_internet():
    if not session.get('authenticated'):
        return redirect('/login')
    ip = request.remote_addr
    message = ''
    if request.method == 'POST':
        inet = request.form.get('inet')
        if inet not in INTERFACE_MARKS:
            message = "❌ اینترنت انتخاب شده نامعتبر است"
        else:
            try:
                ssh_command(f'/ip firewall mangle remove [find comment="Internet Switcher {ip}"]')
                ssh_command(
                    f'/ip firewall mangle add chain=prerouting src-address={ip} action=mark-routing new-routing-mark={INTERFACE_MARKS[inet]} passthrough=yes comment="Internet Switcher {ip}"'
                )
                message = "✅ اینترنت با موفقیت تنظیم شد"
            except Exception as e:
                message = f"❌ خطا: {e}"
    return render_template('change_internet.html', message=message, interfaces=INTERFACE_MARKS)


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session.get('role') != 'admin':
        return redirect('/')
    try:
        output = ssh_command('/ip firewall mangle print where comment~"Internet Switcher"')
    except Exception as e:
        output = f"❌ خطا در دریافت اطلاعات: {e}"
    return render_template('admin.html', rules=output)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=WEB_PORT)
