from routeros_api import RouterOsApiPool
import ssl

def connect_router(ip, username, password, port=8728):
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        api_pool = RouterOsApiPool(
            host=ip,
            username=username,
            password=password,
            port=port,
            use_ssl=False,
            plaintext_login=True,
            ssl_context=ssl_context
        )
        api = api_pool.get_api()
        return api, api_pool
    except Exception as e:
        print(f"خطا در اتصال به روتر: {e}")
        return None, None

def get_pppoe_users(api):
    try:
        users_resource = api.get_resource("/ppp/secret")
        return users_resource.get()
    except Exception as e:
        print(f"خطا در دریافت لیست کاربران: {e}")
        return []

def add_pppoe_user(api, username, password, profile="default"):
    try:
        users_resource = api.get_resource("/ppp/secret")
        users_resource.add(name=username, password=password, service="pppoe", profile=profile)
        return True
    except Exception as e:
        print(f"خطا در افزودن کاربر: {e}")
        return False

def remove_pppoe_user(api, username):
    try:
        users_resource = api.get_resource("/ppp/secret")
        users = users_resource.get()
        for user in users:
            if user["name"] == username:
                users_resource.remove(id=user["id"])
                return True
        return False
    except Exception as e:
        print(f"خطا در حذف کاربر: {e}")
        return False
