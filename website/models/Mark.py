from website import db
from flask_login import UserMixin

class Mark(db.Model):
    """
    Represents a subject in the system.

    Attributes:
        id (int): The unique identifier of the subject.
        score (int): The score obtained in the subject.
        percentage (str): The percentage obtained in the subject.
        student_id (int): The ID of the student associated with the subject.
        subject_id (int): The ID of the subject.

    Relationships:
        student (Student): The student associated with the subject.
        subject (Subject): The subject associated with the subject.
        school (School): The school associated with the subject.

    Methods:
        __repr__() -> str: Returns a string representation of the subject object.

    """

    __tablename__ = "mark"

    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Integer, nullable=False)
    percentage = db.Column(db.String(80))
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'))
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'))

    student = db.relationship('Student')
    subject = db.relationship('Subject')

    school = db.relationship('School')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Subject --name {self.name} from --school {self.school.id}"