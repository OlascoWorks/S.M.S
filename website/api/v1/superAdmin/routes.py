from flask import request, jsonify, redirect, render_template, url_for, make_response, current_app, g
from flask_login import login_required, logout_user, login_user, current_user
import bcrypt, uuid, re
from datetime import datetime, timedelta
from website import db
from website.models import User, RefreshToken, SuperAdmin, Admin, ClassRoom, Guardian, School, Student, Subject, Teacher
from website.api.v1.user.controllers import token_required, create_access_token, generate_refresh_token, try_refresh, make_error_response, verify_inputs, make_updates
from website.api.v1.superAdmin.controllers import handle_unauthorization, first_things_first
from website.api import auth, sAuth, BASE_URL

@sAuth.route('/super-admin/create', methods=['GET', 'POST'])
def super_admin_signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        role = request.form.get('role')
        phone_number = request.form.get('phone_number')

        superAdmin = SuperAdmin.query.filter_by(first_name=first_name,last_name=last_name,email=email,phone_number=phone_number).first()

        if superAdmin:
            return make_error_response("User already exists"), 400
        if password != confirm_password:
            return make_error_response("Passwords don't match"), 400
        try:
            if verify_inputs([[first_name, str], [last_name, str], [email, str], [int(phone_number), int]]):
                return make_error_response("Invalid input type(s)"), 400
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
            new_superAdmin = SuperAdmin(id=user_id, first_name=first_name, last_name=last_name, email=email, password=hashed_password, role=role, phone_number=phone_number)
            db.session.add(new_superAdmin)
            new_user = User(role=role, person_id=user_id)
            db.session.add(new_superAdmin)
            db.session.commit()
        except:  return make_error_response("An internal error occurred"), 500

        login_user(new_user, remember=False)
        response = make_response(f"<script>window.location.href='{BASE_URL}'</script>")
        response.set_cookie('X-access-token', value=access_token, expires=datetime.now() + timedelta(minutes=3), secure=True, httponly=True, samesite='Strict')
        response.set_cookie('X-refresh-token', value=str(refresh_token.token), expires=datetime.now() + timedelta(days=3), secure=True, httponly=True, samesite='Strict')

        return response

    return render_template('signup.html')

@sAuth.route('/super-admin/login', methods=['GET', 'POST'])
def super_admin_login():
    if request.method == 'POST':
        full_name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        first_name, last_name = full_name.split()
        superAdmin = User.query.filter_by(first_name,last_name,email=email).first()

        if superAdmin:
            try:
                if bcrypt.checkpw(password.encode('utf-8'), superAdmin.password):
                    data = {
                        "id": superAdmin.id,
                        "exp": datetime.now() + timedelta(minutes=3)
                    }
                    access_token = create_access_token(data)
                    refresh_token = generate_refresh_token(superAdmin.id)

                    superAdmin.token = refresh_token
                    db.session.commit()
                    login_user(superAdmin)

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
    
    return render_template('super_login.html')


#####################
###    ADMINS    ###
@login_required
@token_required
@sAuth.route('/admin/create', methods=['POST'])
def create_admin(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        gender = request.form.get('gender')
        address = request.form.get('address')
        date_of_birth = request.form.get('date_of_birth')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')
        role = request.form.get('role')
        phone_number = request.form.get('phone_number')

        admin = Admin.query.filter_by(first_name=first_name,last_name=last_name,email=email,phone_number=phone_number,school_id=g.school_id).first()

        if admin:
            return make_error_response("Admin already exists"), 400
        if password != confirm_password:
            return make_error_response("Passwords don't match"), 400
        try:
            if verify_inputs([[first_name, str], [last_name, str], [email, str], [int(phone_number), int]]):
                return make_error_response("Invalid input type(s)"), 400
        except:  return make_error_response("An internal error occurred"), 500
        
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        user_id = uuid.uuid4().hex

        try:
            new_admin = Admin(id=user_id, first_name=first_name, last_name=last_name, email=email, gender=gender, address=address, dob=date_of_birth, password=hashed_password, role=role, phone_number=phone_number,school_id=g.school_id)
            db.session.add(new_admin)
            new_user = User(role=role, person_id=user_id)
            db.session.add(new_user)
            db.session.commit()
        except:  return make_error_response("An internal error occurred"), 500

        response = make_response(f"<script>window.location.href='{BASE_URL}'</script>")

        return response

    return render_template('signup.html')

@login_required
@token_required
@sAuth.route('/admin/delete', methods=['DELETE'])
def delete_admin(currentUser, access_token):
    first_things_first(currentUser)

    name, email = request.args
    first_name, last_name = name

    admin = Admin.query.filter_by(first_name=first_name,last_name=last_name,email=email,school_id=g.school_id)
    if not admin:
        return make_error_response("Admin does not exist"), 400
    
    db.session.delete(admin)
    db.session.commit()

@login_required
@token_required
@sAuth.route('/admin/update', methods=['GET', 'PUT'])
def update_admin(currentUser, access_token):
    first_things_first(currentUser)
    if request.method == 'PUT':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        gender = request.form.get('gender')
        address = request.form.get('address')
        date_of_birth = request.form.get('date_of_birth')
        phone_number = request.form.get('phone_number')

        admin = Admin.query.filter_by(first_name=first_name,last_name=last_name,email=email,school_id=g.school_id).first()

        if not admin:
            return make_error_response("Admin does not exists"), 400
        
        make_updates(fields=['first_name', 'last_name', 'gender', 'email', 'phone_number', 'address', 'dob'], values=[first_name, last_name, gender, email, phone_number, address, date_of_birth], obj=admin)




##########################
###    CLASSROOMS    ####
@login_required
@token_required
@sAuth.route('/classroom/create', methods=['GET', 'POST'])
def create_classroom(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'POST':
        name = request.form.get('first_name')

        classroom = ClassRoom.query.filter_by(name=name,school_id=g.school_id).first()

        if classroom:
            return make_error_response("Class already exists"), 400
        try:
            if verify_inputs([[name, str]]):
                return make_error_response("Invalid input type(s)"), 400
        except:  return make_error_response("An internal error occurred"), 500

        try:
            new_classroom = ClassRoom(name=name,school_id=g.school_id)
            db.session.add(new_classroom)
            db.session.commit()
        except:  return make_error_response("An internal error occurred"), 500

        response = make_response(f"<script>window.location.href='{BASE_URL}'</script>")

        return response

    return render_template('signup.html')

@login_required
@token_required
@sAuth.route('/classroom/delete', methods=['DELETE'])
def delete_classroom(currentUser, access_token):
    first_things_first(currentUser)

    name = request.args.get('name')

    classroom = ClassRoom.query.filter_by(name=name,school_id=g.school_id)
    if not classroom:
        return make_error_response("Class does not exist"), 400
    
    db.session.delete(classroom)
    db.session.commit()

@login_required
@token_required
@sAuth.route('/classroom/update', methods=['GET', 'PUT'])
def update_classroom(currentUser, access_token):
    first_things_first(currentUser)
    if request.method == 'PUT':
        name = request.form.get('name')

        classroom = ClassRoom.query.filter_by(name=name,school_id=g.school_id).first()

        if not classroom:
            return make_error_response("Class does not exists"), 400
    
        make_updates(fields=['name'], values=[name])




########################
###    GUARDIANS    ###
@login_required
@token_required
@sAuth.route('/guardian/create', methods=['GET', 'POST'])
def create_guardian(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        guardian = Guardian.query.filter_by(name=name,email=email,school_id=g.school_id).first()

        if guardian:
            return make_error_response("Guardian already exists"), 400
        if password != confirm_password:
            return make_error_response("Passwords don't match"), 400
        try:
            if verify_inputs([[name, str], [email, str], [int(phone_number), int]]):
                return make_error_response("Invalid input type(s)"), 400
        except:  return make_error_response("An internal error occurred"), 500
        
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        try:
            new_guardian = Guardian(name=name,email=email,phone_number=phone_number,password=hashed_password,school_id=g.school_id)
            db.session.add(new_guardian)
            db.session.commit()
            new_user = User(role='Teacher', person_id=new_guardian.id)
            db.session.add(new_user)
            db.session.commit()
        except:  return make_error_response("An internal error occurred"), 500

        response = make_response(f"<script>window.location.href='{BASE_URL}'</script>")

        return response

    return render_template('signup.html')

@login_required
@token_required
@sAuth.route('/guardian/delete', methods=['DELETE'])
def delete_guardian(currentUser, access_token):
    first_things_first(currentUser)

    name, email = request.args

    guardian = Guardian.query.filter_by(name=name,email=email,school_id=g.school_id)
    if not guardian:
        return make_error_response("Guardian does not exist"), 400

    db.session.delete(guardian)
    db.session.commit()

@login_required
@token_required
@sAuth.route('/guardian/update', methods=['GET', 'PUT'])
def update_guardian(currentUser, access_token):
    first_things_first(currentUser)
    if request.method == 'PUT':
        name = request.form.get('name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')

        guardian = Guardian.query.filter_by(name=name,email=email,school_id=g.school_id).first()

        if not guardian:
            return make_error_response("Guardian does not exists"), 400
        
        make_updates(fields=['name', 'email', 'phone_number'], values=[name, email, phone_number], obj=guardian)




#####################
###    SCHOOL    ###
@login_required
@token_required
@sAuth.route('/school/delete', methods=['DELETE'])
def delete_school(currentUser, access_token):
    first_things_first(currentUser)

    school = School.query.filter_by(id=g.school_id)
    if not school:
        return make_error_response("School does not exist"), 400
    
    db.session.delete(school)
    db.session.commit()

@login_required
@token_required
@sAuth.route('/school/update', methods=['GET', 'PUT'])
def update_school(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'PUT':
        name = request.form.get('name')
        short_name = request.form.get('short_name')
        motto = request.form.get('motto')
        country = request.form.get('country')
        state = request.form.get('state')
        district = request.form.get('district')
        zipCode = request.form.get('z-code')
        address = request.form.get('address')
        email1 = request.form.get('email1')
        email2 = request.form.get('email2')
        contact = request.form.get('contact')

        school = School.query.filter_by(id=g.school_id).first()

        if not school:
            return make_error_response("School does not exists"), 400
        
        make_updates(fields=['name', 'short_name', 'motto', 'country', 'state', 'district', 'zip_code', 'email1', 'email2'], values=[name,short_name,motto,country,state,district,zipCode,email1,email2], obj=school)




######################
###   TEACHERS    ###
@login_required
@token_required
@sAuth.route('/teacher/create', methods=['GET', 'POST'])
def create_teacher(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        gender = request.form.get('gender')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        date_of_birth = request.form.get('dob')
        working_since = request.form.get('working_since')
        subject_id = request.form.get('subject')
        classroom_id = request.form.get('classroom')

        teacher = Teacher.query.filter_by(first_name=first_name,last_name=last_name,email=email,school_id=g.school_id).first()

        if teacher:
            return make_error_response("Teacher already exists"), 400
        try:
            if verify_inputs([[first_name, str], [last_name, str], [email, str], [int(phone_number), int], [address, str]]):
                return make_error_response("Invalid input type(s)"), 400
        except:  return make_error_response("An internal error occurred"), 500
        
        salt = bcrypt.gensalt()
        password = f"{first_name.capitalize}.{last_name.capitalize}"
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        try:
            new_teacher = Teacher(first_name=first_name,last_name=last_name,gender=gender,email=email,phone_number=phone_number,address=address,dob=date_of_birth,password=hashed_password,working_since=working_since,subject_id=subject_id,classroom_id=classroom_id,school_id=g.school_id)
            db.session.add(new_teacher)
            db.session.commit()
            new_user = User(role='Teacher', person_id=new_teacher.id)
            db.session.add(new_user)
            db.session.commit()
        except:  return make_error_response("An internal error occurred"), 500

        response = make_response(f"<script>window.location.href='{BASE_URL}'</script>")

        return response

    return render_template('signup.html')

@login_required
@token_required
@sAuth.route('/teacher/delete', methods=['DELETE'])
def delete_teacher(currentUser, access_token):
    first_things_first(currentUser)

    name, email = request.args
    first_name, last_name = name

    teacher = Teacher.query.filter_by(first_name=first_name,last_name=last_name,email=email,school_id=g.school_id)
    if not teacher:
        return make_error_response("Teacher does not exist"), 400
    
    db.session.delete(teacher)
    db.session.commit()

@login_required
@token_required
@sAuth.route('/teacher/update', methods=['GET', 'PUT'])
def update_teacher(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'PUT':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        gender = request.form.get('gender')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        date_of_birth = request.form.get('dob')
        password = request.form.get('password')
        working_since = request.form.get('working_since')

        teacher = Teacher.query.filter_by(first_name=first_name,last_name=last_name,email=email,school_id=g.school_id).first()

        if not teacher:
            return make_error_response("Teacher does not exists"), 400
        
        make_updates(fields=['first_name', 'last_name', 'gender', 'email', 'phone_number', 'address', 'dob', 'password', 'working_since'], values=[first_name, last_name, gender, email, phone_number, address, date_of_birth, password, working_since], obj=teacher)




#####################
###   SUBJECTS   ###
@login_required
@token_required
@sAuth.route('/subject/create', methods=['GET', 'POST'])
def create_subject(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'POST':
        name = request.form.get('subject')

        subject = Subject.query.filter_by(name=name,school_id=g.school_id).first()

        if subject:
            return make_error_response("Subject already exists"), 400
        try:
            if verify_inputs([[name, str]]):
                return make_error_response("Invalid input type(s)"), 400
        except:  return make_error_response("An internal error occurred"), 500

        try:
            new_teacher = Subject(name=name,school_id=g.school_id)
            db.session.add(new_teacher)
            db.session.commit()
        except:  return make_error_response("An internal error occurred"), 500

        response = make_response(f"<script>window.location.href='{BASE_URL}'</script>")

        return response

    return render_template('signup.html')

@login_required
@token_required
@sAuth.route('/subject/delete', methods=['DELETE'])
def delete_subject(currentUser, access_token):
    first_things_first(currentUser)

    name = request.args

    subject = Subject.query.filter_by(name=name,school_id=g.school_id)
    if not subject:
        return make_error_response("Subject does not exist"), 400
    
    db.session.delete(subject)
    db.session.commit()

@login_required
@token_required
@sAuth.route('/subject/update', methods=['GET', 'PUT'])
def update_subject(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'PUT':
        name = request.form.get('name')

        subject = Subject.query.filter_by(name=name,school_id=g.school_id).first()

        if not subject:
            return make_error_response("Subject does not exists"), 400
        
        make_updates(fields=['name'], values=[name], obj=subject)




#######################
###    STUDENTS    ###
@login_required
@token_required
@sAuth.route('/student/create', methods=['GET', 'POST'])
def create_student(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        middle_name = request.form.get('middle_name')
        student_id = request.form.get('student_id')
        gender = request.form.get('gender')
        address = request.form.get('address')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        date_of_birth = request.form.get('date_of_birth')
        guardian_id = request.form.get('guardian')
        classroom_id = request.form.get('class')

        student = Student.query.filter_by(student_id=student_id,school_id=g.school_id).first()

        if student:
            return make_error_response("Student already exists"), 400
        try:
            if verify_inputs([[first_name, str], [last_name, str], [middle_name, str], [student_id, int], [address, str], [int(phone_number), int]]):
                return make_error_response("Invalid input type(s)"), 400
        except:  return make_error_response("An internal error occurred"), 500

        try:
            new_student = Student(first_name=first_name,last_name=last_name,middle_name=middle_name,student_id=student_id,gender=gender,address=address,email=email,password=student_id,phone_number=phone_number,dob=date_of_birth,guardian_id=guardian_id,classroom_id=classroom_id,school_id=g.school_id)
            db.session.add(new_student)
            db.session.commit()
            new_user = User(role='Student', person_id=new_student.id)
            db.session.add(new_user)
            db.session.commit()
        except:  return make_error_response("An internal error occurred"), 500
        
        response = make_response(f"<script>window.location.href='{BASE_URL}'</script>")

        return response

    return render_template('signup.html')

@login_required
@token_required
@sAuth.route('/student/delete', methods=['DELETE'])
def delete_student(currentUser, access_token):
    first_things_first(currentUser)

    name, id = request.args
    first_name, last_name = name

    student = Student.query.filter_by(first_name=first_name,last_name=last_name,student_id=id,school_id=g.school_id)
    if not student:
        return make_error_response("Student does not exist"), 400
    
    db.session.delete(student)
    db.session.commit()

@login_required
@token_required
@sAuth.route('/student/update', methods=['GET', 'PUT'])
def update_student(currentUser, access_token):
    first_things_first(currentUser)

    if request.method == 'PUT':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        middle_name = request.form.get('middle_name')
        student_id = request.form.get('student_id')
        gender = request.form.get('gender')
        address = request.form.get('address')
        phone_number = request.form.get('phone_number')
        email = request.form.get('email')
        date_of_birth = request.form.get('date_of_birth')

        student = Student.query.filter_by(first_name=first_name,last_name=last_name,student_id=student_id,school_id=g.school_id).first()

        if not student:
            return make_error_response("Student does not exists"), 400
        
        make_updates(fields=['first_name', 'last_name', 'middle_name', 'student_id', 'gender', 'email', 'phone_number', 'address', 'dob'], values=[first_name, last_name, middle_name, student_id, gender, email, phone_number, address, date_of_birth], obj=student)