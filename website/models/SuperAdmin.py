from website import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class SuperAdmin(db.Model, UserMixin):
    """
    Represents a super admin user in the system.

    Attributes:
        id (int): The unique identifier of the super admin.
        first_name (str): The first name of the super admin.
        last_name (str): The last name of the super admin.
        email (str): The email address of the super admin.
        gender (str): The gender of the super admin.
        address (str): The address of the super admin.
        dob (str): The date of birth of the super admin (optional).
        password (str): The password of the super admin.
        role (str): The role of the super admin.
        phone_number (str): The phone number of the super admin.

    Relationships:
        school (School): The school associated with the super admin.

    Methods:
        __repr__() -> str: Returns a string representation of the super admin object.

    """

    __tablename__ = "superAdmin"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    # Picture = db.Column(db.Image, nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    gender = db.Column(db.String(80), nullable=False)
    address = db.Column(db.String(80), nullable=False)
    dob = db.Column(db.String(80), nullable=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(24), nullable=False)
    phone_number = db.Column(db.String(24), nullable=False, unique=True)

    school = db.relationship('School')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Admin --name {self.first_name} from --school {self.school.id}"