import ipaddress
from routeros_api import RouterOsApiPool, exceptions
import os
import json

API_HOST = os.environ.get("API_HOST", "172.30.30.254")
API_USER = os.environ.get("API_USER", "API")
API_PASS = os.environ.get("API_PASS", "API")
API_PORT = int(os.environ.get("API_PORT", 8728))

SETTINGS_FILE = "settings.json"

# اتصال به API میکروتیک
def connect_api():
    try:
        api_pool = RouterOsApiPool(
            API_HOST,
            username=API_USER,
            password=API_PASS,
            port=API_PORT,
            plaintext_login=True
        )
        return api_pool.get_api()
    except exceptions.RouterOsApiConnectionError as e:
        print(f"❌ اتصال به میکروتیک ناموفق: {e}")
        return None

# بارگذاری و ذخیره تنظیمات
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

def save_settings(settings):
    with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)

# گرفتن لیست routing tables
def fetch_routing_tables(api):
    return api.get_resource('/routing/table').get()

# گرفتن لیست اینترفیس‌ها
def fetch_interfaces(api):
    return api.get_resource('/interface/ethernet').get()

# حذف منگل کاربر
def remove_user_mangle(api, user_ip):
    mangle = api.get_resource('/ip/firewall/mangle')
    rules = mangle.get()
    for rule in rules:
        comment = rule.get('comment', '')
        if comment in [f"user:{user_ip}", f"EXCEPTION: {user_ip}"]:
            mangle.remove(id=rule['id'])

# افزودن منگل برای کاربر
def add_user_mangle(api, user_ip, routing_mark):
    mangle = api.get_resource('/ip/firewall/mangle')
    
    # حذف قوانین قبلی فقط برای اطمینان
    remove_user_mangle(api, user_ip)

    # اضافه کردن استثنا برای دسترسی به سایت و خود میکروتیک
    mangle.add(
        chain="prerouting",
        src_address=user_ip,
        dst_address=API_HOST,
        action="accept",
        comment=f"EXCEPTION: {user_ip}"
    )

    # قانون اصلی با مارک روت
    mangle.add(
        chain='prerouting',
        src_address=user_ip,
        action='mark-routing',
        new_routing_mark=routing_mark,
        passthrough='yes',
        comment=f"user:{user_ip}"
    )

# تنظیم روت پیش‌فرض
def set_default_route(api, routing_table, gateway):
    routes = api.get_resource('/ip/route')
    routes.add(
        dst_address="0.0.0.0/0",
        gateway=gateway,
        routing_table=routing_table,
        check_gateway="ping"
    )

# ایجاد روت جدول-اینترفیس
def create_table_routes(api, table_name, interface_name):
    ip_routes = api.get_resource('/ip/route')
    ip_routes.add(
        dst_address="0.0.0.0/0",
        gateway=interface_name,
        routing_table=table_name,
        check_gateway="ping"
    )

# گرفتن DHCP لیست
def get_dhcp_leases(api):
    dhcp = api.get_resource("/ip/dhcp-server/lease")
    return dhcp.get()

# گرفتن روت پیش‌فرض
def get_default_route(api):
    routes = api.get_resource('/ip/route').get()
    for r in routes:
        if r.get('dst-address') == '0.0.0.0/0' and 'routing-table' in r:
            return r['routing-table']
    return "main"

# اعمال روت‌ها از map جدول-اینترفیس
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
                print(f"خطا در اضافه کردن روت برای جدول {table}: {e}")

# گرفتن گیت‌وی برای هر اینترفیس
def get_interface_gateways(api):
    routes = api.get_resource("/ip/route").get()
    gateways = {}

    # از روت‌ها
    for r in routes:
        iface = r.get("interface")
        gw = r.get("gateway")
        dst = r.get("dst-address")

        if iface and gw:
            gateways[iface] = gw

    # از DHCP Client
    dhcp_clients = api.get_resource("/ip/dhcp-client").get()
    for client in dhcp_clients:
        iface = client.get("interface")
        gw = client.get("gateway")
        status = client.get("status")

        if iface and gw and status == "bound":
            gateways[iface] = gw

    return gateways
