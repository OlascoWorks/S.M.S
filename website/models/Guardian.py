from website import db
from flask_login import UserMixin

class Guardian(db.Model, UserMixin):
    """
    Represents a guardian in the system.

    Attributes:
        id (int): The unique identifier of the guardian.
        name (str): The name of the guardian.
        email (str): The email address of the guardian (optional).
        password (str): The password of the guardian.
        phone_number (int): The phone number of the guardian.

    Relationships:
        ward (Student): The student associated with the guardian.
        school (School): The school associated with the guardian.

    Methods:
        __repr__() -> str: Returns a string representation of the guardian object.

    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    # Picture = db.Column(db.Image)
    email = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(80))
    phone_number = db.Column(db.String(24), nullable=False)

    ward = db.relationship('Student')

    school = db.relationship('School')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Subject --name {self.name} from --school {self.school.id}"