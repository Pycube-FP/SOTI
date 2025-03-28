from flask import render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, current_user
from app.auth import bp
from app.auth.forms import LoginForm
from app.models import User

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        current_app.logger.info(f'Login attempt for email: {form.email.data}')
        user = User.query.filter_by(email=form.email.data).first()
        
        if user is None:
            current_app.logger.warning(f'User not found: {form.email.data}')
            flash('Invalid email or password', 'error')
            return redirect(url_for('auth.login'))
            
        if not user.check_password(form.password.data):
            current_app.logger.warning(f'Invalid password for user: {form.email.data}')
            flash('Invalid email or password', 'error')
            return redirect(url_for('auth.login'))
        
        current_app.logger.info(f'Successful login for user: {form.email.data}')
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        return redirect(next_page or url_for('main.dashboard'))
        
    if form.errors:
        current_app.logger.error(f'Form validation errors: {form.errors}')
        
    return render_template('auth/login.html', title='Sign In', form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login')) 