from flask import request, jsonify, redirect, render_template, url_for, make_response, current_app
from flask_login import login_required, logout_user, login_user, current_user
import bcrypt, uuid, re
from datetime import datetime, timedelta
from website import db
from website.models import User, RefreshToken, Teacher
from website.api.v1.user.controllers import token_required, create_access_token, generate_refresh_token, try_refresh, make_error_response, verify_inputs

from website.api import auth, BASE_URL


@auth.route('/teacher/login', methods=['GET', 'POST'])
def teacher_login():
    if request.method == 'POST':
        full_name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        first_name, last_name = full_name.split()

        teacher = Teacher.query.filter_by(first_name=first_name,last_name=last_name,email=email).first()

        if teacher:
            try:
                if bcrypt.checkpw(password.encode('utf-8'), teacher.password):
                    data = {
                        "id": teacher.id,
                        "exp": datetime.now() + timedelta(minutes=3)
                    }
                    access_token = create_access_token(data)
                    refresh_token = generate_refresh_token(teacher.id)

                    teacher.token = refresh_token
                    db.session.commit()
                    login_user(teacher)

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