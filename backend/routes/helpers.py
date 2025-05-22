import json
import ipaddress
import os
from flask import request
from routeros_api import RouterOsApiPool, exceptions

SETTINGS_FILE = "settings.json"

# ---------------------- اتصال به MikroTik ----------------------
def connect_api():
    try:
        pool = RouterOsApiPool(
            os.environ.get("API_HOST", "172.30.30.254"),
            username=os.environ.get("API_USER", "API"),
            password=os.environ.get("API_PASS", "API"),
            port=int(os.environ.get("API_PORT", 8728)),
            plaintext_login=True
        )
        return pool.get_api()
    except exceptions.RouterOsApiConnectionError as e:
        print(f"❌ اتصال به میکروتیک ناموفق: {e}")
        return None

# ---------------------- گرفتن آی‌پی کاربر ----------------------
def get_user_ip():
    return request.headers.get('X-Real-IP') or request.remote_addr

# ---------------------- بارگذاری تنظیمات ----------------------
def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {
        "routing_tables": {},
        "interfaces": {},
        "routes": {},
        "table_interface_map": {}
    }

# ---------------------- ذخیره تنظیمات ----------------------
def save_settings(settings):
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)

# ---------------------- لیست جدول‌های روت ----------------------
def fetch_routing_tables(api):
    return api.get_resource('/routing/table').get()

# ---------------------- لیست اینترفیس‌ها ----------------------
def fetch_interfaces(api):
    return api.get_resource('/interface/ethernet').get()

# ---------------------- بررسی IP مجاز ----------------------
def is_allowed_network(ip):
    allowed = os.environ.get("ALLOWED_NETWORKS", "").split(",")
    try:
        ip_addr = ipaddress.ip_address(ip)
        for net in allowed:
            net = net.strip()
            if "-" in net:
                start_ip, end_ip = net.split("-")
                if ipaddress.ip_address(start_ip) <= ip_addr <= ipaddress.ip_address(end_ip):
                    return True
            else:
                net_obj = ipaddress.ip_network(net.strip(), strict=False)
                if ip_addr in net_obj:
                    return True
    except Exception:
        return False
    return False

# ---------------------- لیست کاربران DHCP ----------------------
def get_dhcp_leases(api):
    dhcp = api.get_resource("/ip/dhcp-server/lease")
    return dhcp.get()

# ---------------------- حذف منگل کاربر ----------------------
def remove_user_mangle(api, user_ip):
    mangle = api.get_resource('/ip/firewall/mangle')
    rules = mangle.get()
    for rule in rules:
        comment = rule.get('comment', '')
        if comment in [f"user:{user_ip}", f"EXCEPTION: {user_ip}"]:
            mangle.remove(id=rule['id'])

# ---------------------- اضافه کردن منگل کاربر ----------------------
def add_user_mangle(api, user_ip, routing_mark):
    mangle = api.get_resource('/ip/firewall/mangle')
    remove_user_mangle(api, user_ip)
    mangle.add(
        chain="prerouting",
        src_address=user_ip,
        dst_address=os.environ.get("API_HOST", "172.30.30.254"),
        action="accept",
        comment=f"EXCEPTION: {user_ip}"
    )
    mangle.add(
        chain="prerouting",
        src_address=user_ip,
        action="mark-routing",
        new_routing_mark=routing_mark,
        passthrough="yes",
        comment=f"user:{user_ip}"
    )

# ---------------------- اعمال روت جدول‌ها ----------------------
def apply_table_routes(api, table_interface_map):
    route_res = api.get_resource('/ip/route')
    routes = route_res.get()

    for table, iface in table_interface_map.items():
        exists = any(r.get('routing-table') == table and r.get('gateway') == iface for r in routes)
        if not exists:
            try:
                route_res.add(
                    dst_address="0.0.0.0/0",
                    gateway=iface,
                    routing_table=table,
                    comment=f"auto-route:{table}"
                )
            except Exception as e:
                print(f"⚠️ خطا در اضافه کردن روت برای جدول {table}: {e}")

# ---------------------- گرفتن گیت‌وی‌های اینترفیس‌ها ----------------------
def get_interface_gateways(api):
    gateways = {}
    routes = api.get_resource("/ip/route").get()
    for r in routes:
        iface = r.get("interface")
        gw = r.get("gateway")
        if iface and gw:
            gateways[iface] = gw
    # بررسی DHCP Clientها
    dhcp_clients = api.get_resource("/ip/dhcp-client").get()
    for client in dhcp_clients:
        iface = client.get("interface")
        gw = client.get("gateway")
        status = client.get("status")
        if iface and gw and status == "bound":
            gateways[iface] = gw
    return gateways

# ---------------------- گرفتن روت پیش‌فرض فعلی ----------------------
def get_default_route(api):
    routes = api.get_resource('/ip/route').get()
    for r in routes:
        if r.get('dst-address') == '0.0.0.0/0' and r.get('routing-table', 'main') == 'main':
            return r
    return None
