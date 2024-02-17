from website import db
from flask_login import UserMixin

# class User(db.Model, UserMixin):
#     id = db.Column(db.String(80), primary_key=True)
#     name = db.Column(db.String(80), nullable=False)
#     email = db.Column(db.String(80), unique=True, nullable=False)
#     password = db.Column(db.String(60), nullable=False)
#     date = db.Column(db.DateTime(timezone=True), default=func.now())
#     token = db.relationship('RefreshToken', uselist=False, backref='user')
#     children = db.relationship('Child')

#     def __repr__(self) -> str:
#         return f'User --name "{self.name}"'
    

# class Child(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(80))
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

#     def __repr__(self) -> str:
#         return f'Child --id "{self.id}"'


class User(db.Model):
    """
    Represents a user in the system.

    Attributes:
        id (int): The unique identifier of the user.
        role (str): The role of the user.
        person_id (int): The ID of the person associated with the user.

    """

    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(24), nullable=False)
    person_id = db.Column(db.Integer, nullable=False)
