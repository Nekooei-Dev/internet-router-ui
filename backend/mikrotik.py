from librouteros import connect
import os

def set_route_for_ip(ip, route):
    try:
        # اتصال به MikroTik API
        api = connect(
            username=os.environ.get("API_USER", "admin"),
            password=os.environ.get("API_PASS", ""),
            host=os.environ.get("MIKROTIK_IP", "172.30.30.254"),
            port=int(os.environ.get("API_PORT", 8728))
        )
        
        # حذف رول قبلی
        for rule in api.path("ip", "firewall", "mangle").select():
            if rule.get("src-address") == ip:
                api.path("ip", "firewall", "mangle").remove(id=rule['.id'])

        # اضافه کردن رول جدید
        api.path("ip", "firewall", "mangle").add(
            chain="prerouting",
            action="mark-routing",
            new_routing_mark=f"to-{route}",
            dst_address_type="!local",
            src_address=ip,
            comment=f"route {ip} -> {route}"
        )
        return True
    except Exception as e:
        print("Mikrotik error:", e)
        return False
