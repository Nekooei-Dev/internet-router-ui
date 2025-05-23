import json
from functools import wraps
from flask import session, redirect, url_for, flash

SETTINGS_FILE = "settings.json"

def read_settings():
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"users": [], "routes": []}

def write_settings(data):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def authenticate(username, password):
    settings = read_settings()
    for user in settings.get("users", []):
        if user["username"] == username and user["password"] == password:
            return user  # شامل role هست
    return None

def login_required(role=None):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            if "username" not in session or "role" not in session:
                flash("برای دسترسی لطفاً وارد شوید", "warning")
                return redirect(url_for("login"))
            if role and session["role"] != role:
                flash("شما اجازه دسترسی به این بخش را ندارید", "danger")
                return redirect(url_for("dashboard"))
            return view_func(*args, **kwargs)
        return wrapper
    return decorator
