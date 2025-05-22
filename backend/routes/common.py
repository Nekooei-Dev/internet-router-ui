from flask import Blueprint, render_template, session, redirect, url_for

common_bp = Blueprint('common', __name__)

@common_bp.route('/')
def home():
    # اگر کاربر لاگین نکرده باشد، به login فرستاده می‌شود
    if 'role' not in session:
        return redirect(url_for('auth.login'))
    return redirect(url_for('common.dashboard'))

@common_bp.route('/dashboard')
def dashboard():
    role = session.get('role')
    return render_template('index.html', role=role)
