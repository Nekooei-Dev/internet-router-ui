from routeros_api import RouterOsApiPool
import os

API_HOST = os.environ.get("API_HOST", "172.30.30.254")
API_USER = os.environ.get("API_USER", "API")
API_PASS = os.environ.get("API_PASS", "API")
API_PORT = int(os.environ.get("API_PORT", 8728))

def get_api_connection():
    api_pool = RouterOsApiPool(API_HOST, username=API_USER, password=API_PASS, port=API_PORT, plaintext_login=True)
    return api_pool.get_api()

def list_users():
    api = get_api_connection()
    users = api.get_resource('/ppp/secret')
    return users.get()

def set_user_internet(username, table):
    api = get_api_connection()
    firewall_mangle = api.get_resource('/ip/firewall/mangle')
    rule_name = f"user-{username}"
    # حذف قوانین قبلی
    for rule in firewall_mangle.get():
        if rule.get('comment') == rule_name:
            firewall_mangle.remove(id=rule['.id'])
    # اضافه‌کردن منگل جدید
    firewall_mangle.add(
        chain="prerouting",
        src_address=username,  # یا IP مربوط به user
        action="mark-routing",
        new_routing_mark=table,
        passthrough="yes",
        comment=rule_name
    )
