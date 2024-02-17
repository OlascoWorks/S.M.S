from website import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class ClassRoom(db.Model):
    """
    Represents a classroom in the system.

    Attributes:
        id (int): The unique identifier of the classroom.
        name (str): The name of the classroom.

    Relationships:
        teacher (Teacher): The teacher associated with the classroom.
        school (School): The school associated with the classroom.

    Methods:
        __repr__() -> str: Returns a string representation of the classroom object.

    """

    __tablename__ = 'classRoom'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(24), unique=True, nullable=False)

    teacher = db.relationship('Teacher')

    school = db.relationship('School')
    school_id = db.Column(db.Integer, db.ForeignKey('school.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Classroom --name {self.name} from --school {self.school.id}"