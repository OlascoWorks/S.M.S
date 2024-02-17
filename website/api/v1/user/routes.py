from flask import request, jsonify, redirect, render_template, url_for, make_response, current_app
from flask_login import login_required, logout_user, login_user, current_user
import bcrypt, uuid, re
from datetime import datetime, timedelta
from website import db
from website.models import User, RefreshToken
from website.api.v1.user.controllers import token_required, create_access_token, generate_refresh_token, try_refresh, make_error_response

from website.api import auth, BASE_URL

@auth.route('/login', methods=['GET', 'POST'])
def login():
    pass

@auth.route('/logout', methods=['POST'])
@login_required
@token_required
def logout(currentUser, access_token):
    if not currentUser:
        try_refresh()
    
    user = current_user
    refresh_token = RefreshToken.query.filter_by(token=user.token.token).first()
    db.session.delete(refresh_token)
    db.session.commit()

    logout_user()

    response = make_response(f"<script>window.location.href='{BASE_URL}/auth/login'</script>")
    response.delete_cookie('X-access-token')
    response.delete_cookie('X-refresh-token')

    return response

@auth.route('/refresh', methods=['POST'])
@login_required
def refresh():
    print('refreshing token...')
    user = current_user
    token = None

    try:
        if 'X-refresh-token' in request.cookies:
            token = request.cookies['X-refresh-token']
        refresh_token = user.token

        if not token:
            return jsonify({"message":"Token is missing"}), 400
        if token != refresh_token.token:
            return jsonify({"message":"Invalid refresh token"}), 400
        if refresh_token.expiration < datetime.now():
            db.session.delete(refresh_token)
            return redirect(url_for('auth.login')), 400
        
        db.session.delete(refresh_token)
        db.session.commit()
        data = {
            "id": user.id,
            "exp": datetime.now() + timedelta(minutes=3)
        }
        access_token = create_access_token(data)
        new_refresh_token = generate_refresh_token(user.id)
        user.token = new_refresh_token
        db.session.commit()

        response = make_response(jsonify({
            "message": "Refreshed successfully",
            "access_token": access_token,
            "refresh_token": new_refresh_token.token
        }))
        response.set_cookie('X-access-token', value=access_token, expires=datetime.now() + timedelta(minutes=3), secure=True, httponly=True, samesite='Strict')
        response.set_cookie('X-refresh-token', value=str(refresh_token.token), expires=datetime.now() + timedelta(days=3), secure=True, httponly=True, samesite='Strict')

        return response
    except Exception as e:
        print(e)
        return f"<h3>An internal error occurred! : {str(e)}. User may already be logged out</h3>", 500

@auth.route('/validate-email', methods=['POST'])
def validate_email():
    email = request.form.get('email')
    email_validate_pattern = r"^\S+@\S+\.\S+$"

    user = User.query.filter_by(email=email).first()

    if user:
        return f"""
        <input type="text" class="w-full h-12 rounded-full bg-bg border-4 border-red-500 text-text text-xs px-14 sm:px-16 py-1 outline-none" placeholder="Enter email here" id="email" name="email"
            hx-post="/auth/validate-email"
            hx-trigger="keyup changed delay:250ms"
            hx-target="#grp"
            hx-swap="innerHTML" value="{email}" required>
            <span class="text-red-500 text-sm font-light mt-3 ml-4">*User aleady exists</span>
        """
    elif not re.match(email_validate_pattern, email):
        return f"""
        <input type="text" class="w-full h-12 rounded-full bg-bg border-4 border-red-500 text-text text-xs px-14 sm:px-16 py-1 outline-none" placeholder="Enter email here" id="email" name="email"
            hx-post="/auth/validate-email"
            hx-trigger="keyup changed delay:250ms"
            hx-target="#grp"
            hx-swap="innerHTML" value="{email}" required>
            <span class="text-red-500 text-sm font-light mt-3 ml-4">*Invalid email</span>
        """
    else:
        return f"""
        <input type="text" class="w-full h-12 rounded-full bg-bg border-4 border-border text-text text-xs px-14 sm:px-16 py-1 outline-none" placeholder="Enter email here" id="email" name="email"
            hx-post="/auth/validate-email"
            hx-trigger="keyup changed delay:250ms"
            hx-target="#grp"
            hx-swap="innerHTML" value="{email}" required>
        """
    

@auth.route('/validate-password', methods=['POST'])
def validate_password():
    password = request.form.get('password')
    password_pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{8,}$"

    if not re.match(password_pattern, password):
        return f"""
        <input type="text" class="w-full h-12 rounded-full bg-bg border-4 border-red-500 text-text text-xs px-14 sm:px-16 py-1 outline-none" placeholder="Enter password here" id="password" name="password"
            hx-post="/auth/validate-password"
            hx-trigger="keyup changed delay:250ms"
            hx-target="#pass-grp"
            hx-swap="innerHTML" value="{password}" required>
            <span class="text-red-500 text-sm font-light mt-3 ml-4">*Password must contain at least 8 characters, one uppercase letter, one lowercase letter and one number</span>
        """
    else:
        return f"""
        <input type="text" class="w-full h-12 rounded-full bg-bg border-4 border-border text-text text-xs px-14 sm:px-16 py-1 outline-none" placeholder="Enter password here" id="password" name="password"
            hx-post="/auth/validate-password"
            hx-trigger="keyup changed delay:250ms"
            hx-target="#pass-grp"
            hx-swap="innerHTML" value="{password}" required>
        """
    

@auth.route('/validate-name', methods=['POST'])
def validate_name():
    name = request.form.get('full_name')
    full_name_pattern = re.compile(r'^[a-zA-Z]+ [a-zA-Z]+$')

    if not full_name_pattern.match(name):
        return f"""
        <input type="text" class="w-full h-12 rounded-full bg-bg border-4 border-red-500 text-text text-xs px-14 sm:px-16 py-1 outline-none" placeholder="Enter password here" id="password" name="password"
            hx-post="/auth/validate-password"
            hx-trigger="keyup changed delay:250ms"
            hx-target="#pass-grp"
            hx-swap="innerHTML" value="{name}" required>
            <span class="text-red-500 text-sm font-light mt-3 ml-4">*Password must contain at least 8 characters, one uppercase letter, one lowercase letter and one number</span>
        """
    else:
        return f"""
        <input type="text" class="w-full h-12 rounded-full bg-bg border-4 border-border text-text text-xs px-14 sm:px-16 py-1 outline-none" placeholder="Enter password here" id="password" name="password"
            hx-post="/auth/validate-password"
            hx-trigger="keyup changed delay:250ms"
            hx-target="#pass-grp"
            hx-swap="innerHTML" value="{name}" required>
        """
    
@auth.route('/not-allowed')
def method_not_allowed():
    return render_template('method_not_allowed.html')