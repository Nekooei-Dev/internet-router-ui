# app.py

import os
from flask import Flask
from backend.routes.auth import auth_bp
from backend.routes.admin import admin_bp
from backend.routes.user import user_bp
from backend.routes.common import common_bp

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "super-secret")

    app.template_folder = "backend/templates"
    app.static_folder = "backend/static"

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(user_bp, url_prefix="/user")
    app.register_blueprint(common_bp)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.environ.get("WEB_PORT", 5000)), debug=True)
