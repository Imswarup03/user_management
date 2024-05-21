
import os
from dotenv import load_dotenv

dotenv_path = os.path.join(os.path.dirname(__file__), '..', '.env')

load_dotenv(dotenv_path)


class Config:
    SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://root:Swarup%40123@localhost/users"
    SECRET_KEY = "JFJSFAW323294B34UY8238RWY83YR293"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    print("SQLALCHEMY_DATABASE_URI",SQLALCHEMY_DATABASE_URI)

