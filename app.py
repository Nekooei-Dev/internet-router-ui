from flask import Flask
from config import Config
from blueprints.admin_routes import admin_bp
from blueprints.user_routes import user_bp
from blueprints.common_routes import common_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # ثبت بلوپرینت‌ها
    app.register_blueprint(common_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)

