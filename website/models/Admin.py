from website import db
from flask_login import UserMixin

class Admin(db.Model, UserMixin):
    """
        Represents an admin user in the system.

        Attributes:
            id (int): The unique identifier of the admin.
            first_name (str): The first name of the admin.
            last_name (str): The last name of the admin.
            email (str): The email address of the admin.
            gender (str): The gender of the admin.
            address (str): The address of the admin.
            dob (str): The date of birth of the admin (optional).
            password (str): The password of the admin.
            role (str): The role of the admin.
            phone_number (int): The phone number of the admin.

        Relationships:
            school (School): The school associated with the admin.

        Methods:
            __repr__() -> str: Returns a string representation of the admin object.

    """

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    # Picture = db.Column(db.Image, nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    gender = db.Column(db.String(80), nullable=False)
    address = db.Column(db.String(80), nullable=False)
    dob = db.Column(db.String(80), nullable=True)
    password = db.Column(db.String(80))
    role = db.Column(db.String(24), nullable=False)
    phone_number = db.Column(db.String(24), nullable=False)

    school = db.relationship('School')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Admin --name {self.first_name} from --school {self.school.id}"