from flask import Flask, render_template, redirect, url_for, request, session
import os

app = Flask(__name__)

# کلید امنیتی اپلیکیشن
app.secret_key = os.environ.get("SECRET_KEY", "default-secret-key")

# تنظیمات برای نمایش ارورهای سفارشی
@app.errorhandler(404)
@app.errorhandler(500)
def error_page(e):
    return render_template("error.html", error=str(e)), e.code if hasattr(e, 'code') else 500

# بعداً routeها از فایل جدا بارگذاری می‌شن:
from routes.common_routes import common_bp
from routes.user_routes import user_bp
from routes.admin_routes import admin_bp

app.register_blueprint(common_bp)
app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("WEB_PORT", 5000)))
