from flask import redirect, url_for, request, g
from website.api import gAuth
from website.models import Guardian, School
from website.api.v1.user.controllers import try_refresh

def isGuardian(user):
    guardian = Guardian.query.filter_by(first_name=user.first_name,last_name=user.last_name,email=user.email,school_id=user.school_id).first()

    if guardian:  return True
    else:  return False

def handle_unauthorization(user):
    if not isGuardian(user):
        return redirect(url_for('auth.login'))
    
    return

def first_things_first(currentUser):
    if not currentUser:
        try_refresh()
    handle_unauthorization(currentUser)
    if not g.school_id:
        return redirect('404.html'), 404

@gAuth.before_request
def before_request():
    school_name = request.subdomain

    school = School.query.filter_by(short_name=school_name).first()
    
    g.school = school if school.id else None