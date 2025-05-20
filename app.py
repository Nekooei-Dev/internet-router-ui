import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from routeros_api import RouterOsApiPool, ApiException
from ipaddress import ip_network, ip_address

app = Flask(__name__)

# تنظیمات از env میکروتیک (یا مقادیر پیش‌فرض)
app.secret_key = os.environ.get("SECRET_KEY", "9f7e2c45b6a14d9a8e4d31f0c5b2a7e1")
API_HOST = os.environ.get("API_HOST", "172.30.30.254")
API_USER = os.environ.get("API_USER", "API")
API_PASS = os.environ.get("API_PASS", "API")
API_PORT = int(os.environ.get("API_PORT", 8728))
WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")
ALLOWED_NETWORKS = [net.strip() for net in os.environ.get(
    "ALLOWED_NETWORKS",
    "172.30.30.0/24,172.32.30.10-172.32.30.40,192.168.1.10"
).split(",")]

# Helper: چک کردن اجازه دسترسی به IP
def ip_allowed(ip_str):
    ip = ip_address(ip_str)
    for net in ALLOWED_NETWORKS:
        if "-" in net:  # Range IP
            start_ip, end_ip = net.split("-")
            if ip_address(start_ip) <= ip <= ip_address(end_ip):
                return True
        else:
            if ip in ip_network(net, strict=False):
                return True
    return False

# اتصال به میکروتیک API
def get_api():
    try:
        api_pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, port=API_PORT, plaintext_login=True)
        api = api_pool.get_api()
        return api, api_pool
    except ApiException as e:
        print(f"API connection error: {e}")
        return None, None

# ... (اینجا ادامه کدهای روتینگ، لاگین، مدیریت اینترنت، تغییر اینترنت کاربر و ... خواهد آمد)
# به خاطر محدودیت طول پیام، بعد از این بخش به ترتیب فایل های قالب و استاتیک رو می فرستم.

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
