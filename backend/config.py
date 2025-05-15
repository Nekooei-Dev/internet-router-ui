import os

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "pass123")
DEFAULT_ROUTE = os.getenv("DEFAULT_ROUTE", "irancell")
SECRET_KEY = os.getenv("SECRET_KEY", "random123")
APP_PORT = int(os.getenv("APP_PORT", "80"))
