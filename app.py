# app.py
import os
from flask import Flask
from backend.routes.auth import auth_bp
from backend.routes.admin import admin_bp
from backend.routes.user import user_bp
from backend.routes.common import common_bp

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "9f7e2c45b6a14d9a8e4d31f0c5b2a7e1")

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(user_bp)
app.register_blueprint(common_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
