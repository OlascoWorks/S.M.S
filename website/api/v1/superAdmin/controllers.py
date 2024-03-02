from flask import redirect, url_for, request, g
from website.api import sAuth
from website.models import SuperAdmin, School
from website.api.v1.user.controllers import try_refresh

def isSuperAdmin(user):
    superAdmin = SuperAdmin.query.filter_by(first_name=user.first_name,last_name=user.last_name,email=user.email,phone_number=user.phone_number,school_id=user.school_id).first()

    if superAdmin:  return True
    else:  return False

def handle_unauthorization(user):
    if not isSuperAdmin(user):
        ###log failed attempt
        return redirect(url_for('auth.login'))
    
    return

def first_things_first(currentUser):
    if not currentUser:
        try_refresh()
    handle_unauthorization(currentUser)
    if not g.school_id:
        return redirect('404.html'), 404

@sAuth.before_request
def before_request():
    school_name = request.subdomain

    school = School.query.filter_by(short_name=school_name).first()
    
    g.school = school if school.id else None