
import mysql.connector
import os
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from configs.email_config import EmailSender

load_dotenv()

# create a db
# Create a connection to the MySQL server (without specifying a database)


def create_db():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password=os.environ.get('MYSQL_PASSWORD')
    )
    # create a cursor object
    cursor = conn.cursor()
    mysql_db = os.environ.get('MYSQL_DB')
    # check if the database exists and create it if it doesn't
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {mysql_db}")

    # Close the cursor and connection
    cursor.close()
    conn.close()
    return True


create_db= create_db()

if create_db:
    db = SQLAlchemy()
    print("DB CREATED SUCCESSFULLY")
    send_email = EmailSender()
    