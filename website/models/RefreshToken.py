from website import db
from datetime import timedelta, datetime
from sqlalchemy.sql import func

class RefreshToken(db.Model):
    """
    Represents a refresh token in the system.

    Attributes:
        id (int): The unique identifier of the refresh token.
        token (str): The refresh token.
        expiration (datetime): The expiration date and time of the refresh token.
        user_id (int): The ID of the user associated with the refresh token.

    """

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(80))
    expiration = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now() + timedelta(days=3))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))