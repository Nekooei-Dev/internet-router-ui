from flask import Flask, request, jsonify, abort
from routeros_api import RouterOsApiPool
import os
from config import ADMIN_USER, ADMIN_PASS, DEFAULT_ROUTE, SECRET_KEY, APP_PORT
from functools import wraps

app = Flask(__name__)

# Basic Auth decorator
def check_auth(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS

def authenticate():
    abort(401, description="Authentication required")

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# Connect to MikroTik router (Local IP assumed)
def connect_to_mikrotik():
    pool = RouterOsApiPool('172.30.30.254', username='admin', password='admin_password', plaintext_login=True)
    api = pool.get_api()
    return pool, api

@app.route('/change-route', methods=['POST'])
@requires_auth
def change_route():
    data = request.json
    if 'route' not in data:
        return jsonify({'error': 'route field missing'}), 400
    
    route_name = data['route']
    if route_name not in ['irancell', 'hamrahaval', 'adsl', 'asiatech']:
        return jsonify({'error': 'invalid route'}), 400

    pool, api = connect_to_mikrotik()
    ip_route = api.get_resource('/ip/route')

    # مثال: تغییر روت پیشفرض به روتر جدید
    try:
        # Disable all default routes first
        default_routes = ip_route.get(dst='0.0.0.0/0')
        for r in default_routes:
            ip_route.set(id=r['id'], disabled='yes')
        
        # Enable only selected route
        routes = ip_route.get(comment__contains=route_name)
        for r in routes:
            ip_route.set(id=r['id'], disabled='no')

        pool.disconnect()
        return jsonify({'status': f'Default route changed to {route_name}'})
    except Exception as e:
        pool.disconnect()
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    return "Internet Router UI Backend Running"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=APP_PORT)
