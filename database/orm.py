from flask_sqlalchemy import SQLAlchemy
import database.database as cd

cd.create_db()
db = SQLAlchemy()