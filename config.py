import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "9f7e2c45b6a14d9a8e4d31f0c5b2a7e1")
    API_HOST = os.environ.get("API_HOST", "172.30.30.254")
    API_USER = os.environ.get("API_USER", "API")
    API_PASS = os.environ.get("API_PASS", "API")
    API_PORT = int(os.environ.get("API_PORT", 8728))

    WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
    WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")

    ALLOWED_NETWORKS = [net.strip() for net in os.environ.get(
        "ALLOWED_NETWORKS",
        "172.30.30.0/24 , 172.32.30.10-172.32.30.40 , 192.168.1.10"
    ).split(",")]
