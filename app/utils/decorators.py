from functools import wraps
from flask import redirect, url_for, session, flash
from typing import Callable

def login_required(f: Callable) -> Callable:
    """
    Decorator to check if user is logged in.
    Redirects to login page if user is not authenticated.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function 