from datetime import datetime
from database.orm import db



class User(db.Model):    
    __tablename__ = 'users_auth' # custom table name 
    id = db.Column(db.Integer,primary_key= True, autoincrement=True)
    username= db.Column(db.String(80),unique=True, nullable = False)
    name = db.Column(db.String(100), nullable=False)
    email= db.Column(db.String(80),unique= True, nullable=False)
    phone_number= db.Column(db.BigInteger, unique= True, nullable= False)
    password = db.Column(db.String(128), nullable= False)
    timestamp= db.Column(db.DateTime, default=datetime.now)
    # timestamp= db.Column(db.DateTime, default=datetime.now)
    
    def __repr__(self):
        # print("Database Created Successfully")
        user = {
            "username":self.username,
            "name":self.name,
            "phone_number":self.phone_number,
        }
        self.user = user
        return f'<MyModel{self.user}>'
    