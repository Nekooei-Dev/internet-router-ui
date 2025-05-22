from flask import Blueprint, render_template, request, session, redirect, url_for, flash
import os

auth_bp = Blueprint('auth', __name__)

WEB_USER_PASSWORD = os.environ.get("WEB_USER_PASSWORD", "123456")
WEB_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "123456789")

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')

        if password == WEB_ADMIN_PASSWORD:
            session['role'] = 'admin'
            flash("با موفقیت وارد شدید به عنوان مدیر", "success")
            return redirect(url_for('common.dashboard'))

        elif password == WEB_USER_PASSWORD:
            session['role'] = 'user'
            flash("با موفقیت وارد شدید به عنوان کاربر", "success")
            return redirect(url_for('common.dashboard'))

        else:
            flash("رمز عبور اشتباه است", "danger")

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("با موفقیت خارج شدید", "info")
    return redirect(url_for('auth.login'))
