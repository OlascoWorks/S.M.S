from website import db
from datetime import datetime

class School(db.Model):
    """
    Represents a school in the system.

    Attributes:
        id (int): The unique identifier of the school.
        name (str): The name of the school.
        short_name (str): The short name of the school.
        motto (str): The motto of the school (optional).
        address (str): The address of the school.
        country (str): The country of the school.
        state (str): The state of the school.
        district (str): The district of the school.
        zip_code (str): The zip code of the school.
        email1 (str): The primary email address of the school.
        email2 (str): The secondary email address of the school.
        contact (str): The contact number of the school.
        website (str): The website URL of the school (optional).
        created_at (datetime): The creation date and time of the school.

    Methods:
        __repr__() -> str: Returns a string representation of the school object.

    """

    __tablename__ = "school"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    short_name = db.Column(db.String(80), nullable=False, unique=True)
    # logo = db.Column(db.Image, nullable=False)
    # backdrop = db.Column(db.Image, nullable=False)
    motto = db.Column(db.String(80))
    address = db.Column(db.String(80), nullable=False)
    country = db.Column(db.String(80), nullable=False)
    state = db.Column(db.String(80), nullable=False)
    district = db.Column(db.String(80), nullable=False)
    zip_code = db.Column(db.String(24), nullable=False)
    email1 = db.Column(db.String(60), nullable=False)
    email2 = db.Column(db.String(60), nullable=False)
    contact = db.Column(db.String(24), nullable=False)
    website = db.Column(db.String(80))
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now())

    def __repr__(self) -> str:
        return f"school --name {self.name}"