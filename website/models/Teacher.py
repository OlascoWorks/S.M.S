from website import db
from flask_login import UserMixin

class Teacher(db.Model, UserMixin):
    """
    Represents a teacher in the system.

    Attributes:
        id (int): The unique identifier of the teacher.
        first_name (str): The first name of the teacher.
        last_name (str): The last name of the teacher.
        gender (str): The gender of the teacher.
        email (str): The email address of the teacher.
        phone_number (str): The phone number of the teacher.
        address (str): The address of the teacher.
        dob (Time): The date of birth of the teacher (optional).
        password (str): The password of the teacher.
        working_since (Time): The date when the teacher started working.
        subject_id (int): The ID of the subject associated with the teacher.
        class_room_id (int): The ID of the class room associated with the teacher.

    Relationships:
        class_room (ClassRoom): The class room associated with the teacher.
        school (School): The school associated with the teacher.

    Methods:
        __repr__() -> str: Returns a string representation of the teacher object.

    """

    id = db.Column(db.Integer, primary_key=True)
    # Picture = db.Column(db.Image, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    gender = db.Column(db.String(8), nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    phone_number = db.Column(db.String(24), unique=True, nullable=False)
    address = db.Column(db.String(80), nullable=False)
    dob = db.Column(db.Time, nullable=True)
    password = db.Column(db.String(80))
    working_since = db.Column(db.Time)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    class_room_id = db.Column(db.Integer, db.ForeignKey('classRoom.id'), nullable=False)

    class_room = db.relationship('ClassRoom')

    school = db.relationship('School')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Teacher --name {self.first_name} {self.last_name} from --school {self.school.id}"