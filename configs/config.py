import os
from dotenv import load_dotenv
from datetime import timedelta
load_dotenv()



SQLALCHEMY_DATABASE_URI= os.environ.get("SQL_ALCHEMY_DATABASE_URI")
SECRET_KEY= os.environ.get("SECRET_KEY")

class Config:
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI
    JWT_SECRET_KEY = SECRET_KEY
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    JWT_TOKEN_LOCATION = ["headers", "cookies", "json","query-string"]
    JWT_REFRESH_TOKEN_LOCATION=["headers", "cookies"]
    JWT_ACCESS_TOKEN_EXPIRES= timedelta(minutes=5)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=3)
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

    print("SQLALCHEMY_DATABASE_URI",SQLALCHEMY_DATABASE_URI)

