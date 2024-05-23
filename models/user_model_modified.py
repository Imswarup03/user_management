from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    __tablename__ = 'users_auth'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    cart = db.Column(db.JSON, default=[])
    isBlocked = db.Column(db.Boolean, default=False)
    address = db.Column(db.String(200))
    refreshToken = db.Column(db.String(256))
    passwordChangedAt = db.Column(db.DateTime)
    passwordResetToken = db.Column(db.String(256))
    passwordResetExpires = db.Column(db.DateTime)

    def __init__(self, username, firstname, lastname, email, mobile, password, role=None):
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.mobile = mobile
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.role = role if role else 'user'

    def is_password_matched(self, entered_password):
        return bcrypt.check_password_hash(self.password, entered_password)

    def create_password_reset_token(self):
        reset_token = secrets.token_hex(32)
        self.passwordResetToken = bcrypt.generate_password_hash(reset_token).decode('utf-8')
        self.passwordResetExpires = datetime.now() + timedelta(minutes=30)
        return reset_token
