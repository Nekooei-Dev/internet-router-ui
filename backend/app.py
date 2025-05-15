from flask import Flask, request, jsonify, abort
from routeros_api import RouterOsApiPool
from config import ADMIN_USER, ADMIN_PASS, DEFAULT_ROUTE, APP_PORT, MIKROTIK_IP, MIKROTIK_USER, MIKROTIK_PASS
from functools import wraps

app = Flask(__name__)

def check_auth(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS

def authenticate():
    return abort(401, description='Authentication required')

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def connect_mikrotik():
    pool = RouterOsApiPool(MIKROTIK_IP, username=MIKROTIK_USER, password=MIKROTIK_PASS, plaintext_login=True)
    api = pool.get_api()
    return pool, api

@app.route('/api/default-route', methods=['GET'])
@requires_auth
def get_default_route():
    return jsonify({'route': DEFAULT_ROUTE})

@app.route('/api/change-route', methods=['POST'])
@requires_auth
def change_route():
    data = request.json
    route_name = data.get('route')
    if route_name not in ['irancell', 'hamrahaval', 'mci', 'asiatech']:
        return jsonify({'error': 'Invalid route selected'}), 400

    pool, api = connect_mikrotik()
    ip_route = api.get_resource('/ip/route')

    try:
        # غیرفعال کردن تمام default routes
        default_routes = ip_route.get(dst='0.0.0.0/0')
        for r in default_routes:
            ip_route.set(id=r['id'], disabled='yes')

        # فعال کردن فقط روت انتخاب شده
        routes = ip_route.get(comment__contains=route_name)
        for r in routes:
            ip_route.set(id=r['id'], disabled='no')

        pool.disconnect()

        # آپدیت مقدار DEFAULT_ROUTE محیطی (فقط در runtime)
        global DEFAULT_ROUTE
        DEFAULT_ROUTE = route_name

        return jsonify({'status': f'Default route changed to {route_name}'})
    except Exception as e:
        pool.disconnect()
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    return 'Internet Router UI Backend Running'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=APP_PORT)
