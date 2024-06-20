from datetime import datetime
from database.settings import db
from flask_bcrypt import Bcrypt
import os 
import pytz
import time


bcrypt = Bcrypt()
class User(db.Model):
    __tablename__ = 'users'
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
    passwordCreatedAt: str = db.Column(db.DateTime)
    passwordChangedAt : str= db.Column(db.DateTime)
    passwordResetToken : str = db.Column(db.String(512))
    passwordResetExpires : str= db.Column(db.BigInteger)
    otp : str = db.Column(db.String(256))
    otpExpiresAt = db.Column(db.BigInteger)
    timestamp = db.Column(db.DateTime, default = datetime.now(pytz.timezone('Asia/Kolkata')))


    def __init__(self, username, firstname, lastname, email, phone_number, password, role=None):
        self.username = username
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.phone_number = phone_number
        self.password = bcrypt.generate_password_hash(password,13).decode('utf-8')
        self.role = role if role else 'user'    
        self.passwordCreatedAt= datetime.now(pytz.timezone('Asia/Kolkata'))

    def __repr__(self):
        # print("Database Created Successfully")
        return f'User {self.username}'
    def set_password_reset_expiration(self):
        try:
            self.passwordResetExpires= int(time.time()) + (15*60)
            print("password expires at",self.passwordResetExpires)
            db.session.commit()
            return {'message':"Success", "stausCode":True}
        except Exception as e:
            print(e)
            return {'message':"Success", "staus":False}
    def generate_and_store_otp(self, otp, salt, secret_key):
        try:
            combined = f"{otp}{salt}{secret_key}"
            hashed_otp = bcrypt.generate_password_hash(combined, 10).decode('utf-8')
            self.otp = hashed_otp
            # Calculate expiration timestamp in milliseconds
            expiration_time = int(time.time()) + (10*60)
            self.otpExpiresAt = expiration_time
            db.session.commit()
            return {'message':"Success", "staus":True}
        except Exception as e:
            print(e)
            return {'message':"Success", "staus":False}
    def update_password(self,password,confirm_password):
        try:
            if password == confirm_password:
                self.password= bcrypt.generate_password_hash(password,13).decode('utf-8')
                self.passwordChangedAt= datetime.now(pytz.timezone('Asia/Kolkata'))
                db.session.commit()
                return {'message':"Success", "staus":True}
        except Exception as e:
            print(e)
            return {'message':"Success", "staus":False}
    

