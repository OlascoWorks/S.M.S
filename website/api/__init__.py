from flask import Blueprint
import os

api = Blueprint('api', __name__)
views = Blueprint('views', __name__)
auth = Blueprint('auth', __name__)
sAuth = Blueprint('sAuth', __name__)
aAuth = Blueprint('aAuth', __name__)
tAuth = Blueprint('tAuth', __name__)
gAuth = Blueprint('gAuth', __name__)

BASE_URL = os.environ.get('BASE_URL')
BASE_URL = 'http://127.0.0.1:5000' if BASE_URL == None else BASE_URL