from website import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class Subject(db.Model):
    """
    Represents a subject in the system.

    Attributes:
        id (int): The unique identifier of the subject.
        name (str): The name of the subject.

    Relationships:
        teacher (Teacher): The teacher associated with the subject.
        school (School): The school associated with the subject.

    Methods:
        __repr__() -> str: Returns a string representation of the subject object.

    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    teacher = db.relationship('Teacher')

    school = db.relationship('School')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Subject --name {self.name} from --school {self.school.id}"