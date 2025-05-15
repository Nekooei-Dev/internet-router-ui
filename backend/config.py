import os

ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASS = os.getenv('ADMIN_PASS', 'pass123')
DEFAULT_ROUTE = os.getenv('DEFAULT_ROUTE', 'irancell')
APP_PORT = int(os.getenv('APP_PORT', 80))
MIKROTIK_IP = os.getenv('MIKROTIK_IP', '172.30.30.254')
MIKROTIK_USER = os.getenv('MIKROTIK_USER', 'admin')
MIKROTIK_PASS = os.getenv('MIKROTIK_PASS', 'admin_password')
