from website import db
from flask_login import UserMixin

students_subjects = db.Table(
    'student_subjects',
    db.Column('Student_id', db.Integer, db.ForeignKey('student.id')),
    db.Column('Subject_id', db.Integer, db.ForeignKey('subject.id'))
)

class Student(db.Model, UserMixin):
    """
    Represents a student in the system.

    Attributes:
        id (int): The unique identifier of the student.
        first_name (str): The first name of the student.
        last_name (str): The last name of the student.
        middle_name (str): The middle name of the student.
        student_id (int): The ID of the student.
        gender (str): The gender of the student.
        address (str): The address of the student.
        phone_number (int): The phone number of the student (optional).
        email (str): The email address of the student (optional).
        dob (Time): The date of birth of the student.
        password (str): The password of the student.
        guardian_id (int): The ID of the guardian associated with the student.
        class_room_id (int): The ID of the class room associated with the student.

    Relationships:
        class_room (ClassRoom): The class room associated with the student.
        guardian (Guardian): The guardian associated with the student.
        subjects (List[Subject]): The subjects associated with the student.
        marks (List[Mark]): The marks associated with the student.
        school (School): The school associated with the student.

    Methods:
        __repr__() -> str: Returns a string representation of the student object.

    """

    __tablename__ = "student"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    middle_name = db.Column(db.String(80), nullable=False)
    # Picture = db.Column(db.Image, nullable=False)
    student_id = db.Column(db.Integer, nullable=False, unique=True)
    gender = db.Column(db.String(8), nullable=False)
    address = db.Column(db.String(80), nullable=False)
    phone_number = db.Column(db.String(24))
    email = db.Column(db.String(80), unique=True)
    dob = db.Column(db.Time, nullable=False)
    password = db.Column(db.String(80))
    guardian_id = db.Column(db.Integer, db.ForeignKey('guardian.id'), nullable=False)
    class_room_id = db.Column(db.Integer, db.ForeignKey('classRoom.id'), nullable=False)

    class_room = db.relationship('ClassRoom')
    guardian = db.relationship('Guardian')
    subjects = db.relationship('Subject', secondary='student_subjects')
    marks = db.relationship('Mark', uselist=True)

    school = db.relationship('School')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Student --name {self.first_name} {self.last_name} from --school {self.school.id}"