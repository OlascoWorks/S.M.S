from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
import os

db = SQLAlchemy()
DB_NAME = 'database.db'

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') if os.environ.get('DATABASE_URL') else f'sqlite:///{DB_NAME}'
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config.from_pyfile('config.py')

    db.init_app(app)

    @app.route('/')
    def home():
        return render_template('base.html')

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html', current_user=current_user)

    from .api import views, auth, sAuth, aAuth, tAuth, gAuth
    from .api.v1.user import login, logout
    
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/auth')
    app.register_blueprint(sAuth, url_prefix='/sAuth')
    app.register_blueprint(aAuth, url_prefix='/aAuth')
    app.register_blueprint(tAuth, url_prefix='/tAuth')
    app.register_blueprint(gAuth, url_prefix='/gAuth')

    from .models import User, Admin, ClassRoom, Guardian, Mark, School, Student, SuperAdmin, Teacher
    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(id)

    return app