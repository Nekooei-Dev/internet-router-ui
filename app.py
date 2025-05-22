from flask import Flask
from backend.routes.auth import auth_bp
from backend.routes.admin import admin_bp
from backend.routes.user import user_bp
from backend.routes.common import common_bp

import os

app = Flask(__name__)

# تنظیم کلید امنیتی از محیط
app.secret_key = os.environ.get("SECRET_KEY", "9f7e2c45b6a14d9a8e4d31f0c5b2a7e1")

# ثبت بلوپرینت‌ها
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp, url_prefix="/admin")
app.register_blueprint(user_bp, url_prefix="/user")
app.register_blueprint(common_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
