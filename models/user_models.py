from datetime import datetime
from database.settings import db
from flask_bcrypt import Bcrypt
import os 
import pytz


bcrypt = Bcrypt()
class User(db.Model):
    __tablename__ = 'users_auth'
    id : int= db.Column(db.Integer, primary_key=True)
    username : str= db.Column(db.String(50), unique=True, nullable=False)
    firstname : str= db.Column(db.String(100), nullable=False)
    lastname : str = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number : int= db.Column(db.BigInteger, unique=True, nullable=False)
    password : str= db.Column(db.String(256), nullable=False)
    role : str= db.Column(db.String(50), nullable=False, default ='user')
    isBlocked : str= db.Column(db.Boolean, default=False)
    address : str = db.Column(db.String(200))
    refreshToken : str = db.Column(db.String(512))
    passwordCreatedAt: str = db.Column(db.String(256))
    passwordChangedAt : str= db.Column(db.DateTime)
    passwordResetToken : str = db.Column(db.String(512))
    passwordResetExpires : str= db.Column(db.DateTime)
    timestamp = db.Column(db.String(256), default = datetime.now(pytz.timezone('Asia/Kolkata')).strftime("%d-%m-%Y, %H:%M:%S"))
    

    def __init__(self, username, firstname, lastname, email, phone_number, password, role=None):
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.phone_number = phone_number
        self.password = bcrypt.generate_password_hash(password,13)
        self.role = role if role else 'user'    
        self.passwordCreatedAt= datetime.now(pytz.timezone('Asia/Kolkata')).strftime("%d-%m-%Y, %H:%M:%S")

    def __repr__(self):
        # print("Database Created Successfully")
        return f'User {self.username}'
    
    




