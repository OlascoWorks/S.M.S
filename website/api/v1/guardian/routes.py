from flask import request, jsonify, redirect, render_template, url_for, make_response, current_app
from flask_login import login_required, logout_user, login_user, current_user
import bcrypt, uuid, re
from datetime import datetime, timedelta
from website import db
from website.models import User, RefreshToken, Guardian
from website.api.v1.user.controllers import token_required, create_access_token, generate_refresh_token, try_refresh, make_error_response, verify_inputs

from website.api import auth, BASE_URL

@auth.route('/guardian/create', methods=['GET', 'POST'])
def guardian_signup():
    if request.method == 'POST':
        name = request.form.get('first_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        phone_number = request.form.get('phone_number')

        guardian = Guardian.query.filter_by(name=name,email=email,phone_number=phone_number).first()

        if guardian:
            return make_error_response("User already exists"), 400
        if password != confirm_password:
            return make_error_response("Passwords don't match"), 400
        try:
            if verify_inputs([[name, str], [int(phone_number), int]]):
                return make_error_response("Invalid input tyoes"), 400
        except:  return make_error_response("An internal error occurred"), 500
        
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        user_id = uuid.uuid4().hex
        data = {
            "id": user_id,
            "exp": datetime.now() + timedelta(minutes=3)
        }
        access_token = create_access_token(data)
        refresh_token = generate_refresh_token(user_id)

        try:
            new_guardian = Guardian(id=user_id, name=name, email=email, password=hashed_password, phone_number=phone_number)
            db.session.add(new_guardian)
            new_user = User(role='Guardian', person_id=user_id)
            db.session.add(new_user)
            db.session.commit()
        except:  return make_error_response("An internal error occurred"), 500

        login_user(new_guardian, remember=False)
        response = make_response(f"<script>window.location.href='{BASE_URL}'</script>")
        response.set_cookie('X-access-token', value=access_token, expires=datetime.now() + timedelta(minutes=3), secure=True, httponly=True, samesite='Strict')
        response.set_cookie('X-refresh-token', value=str(refresh_token.token), expires=datetime.now() + timedelta(days=3), secure=True, httponly=True, samesite='Strict')

        return response

    return render_template('signup.html')

@auth.route('/guardian/login', methods=['GET', 'POST'])
def guardian_login():
    if request.method == 'POST':
        full_name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        first_name, last_name = full_name.split()
        guardian = Guardian.query.filter_by(first_name,last_name,email=email).first()

        if guardian:
            try:
                if bcrypt.checkpw(password.encode('utf-8'), guardian.password):
                    data = {
                        "id": guardian.id,
                        "exp": datetime.now() + timedelta(minutes=3)
                    }
                    access_token = create_access_token(data)
                    refresh_token = generate_refresh_token(guardian.id)

                    guardian.token = refresh_token
                    db.session.commit()
                    login_user(guardian)

                    response = make_response(f"<script>window.location.href='{BASE_URL}'</script>")
                    response.set_cookie('X-access-token', value=access_token, expires=datetime.now() + timedelta(minutes=3), secure=True, httponly=True, samesite='Strict')
                    response.set_cookie('X-refresh-token', value=str(refresh_token.token), expires=datetime.now() + timedelta(days=3), secure=True, httponly=True, samesite='Strict')

                    return response
                else:
                    return make_error_response("Invalid password"), 400
            except Exception as e:
                return make_error_response("An internal error occurred!"), 500
        else:
            return make_error_response("User does not exist"), 400
    
    return render_template('login.html')