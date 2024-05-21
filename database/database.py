
import mysql.connector
import os

# create a db
# Create a connection to the MySQL server (without specifying a database)

def create_db():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Swarup@123"
    )

    # Create a cursor object
    cursor = conn.cursor()
    mysql_db = os.environ.get('MYSQL_DB')
    print("mysql_db",mysql_db)
    # Check if the database exists and create it if it doesn't
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS USERS")

    # Close the cursor and connection
    cursor.close()
    conn.close()
    print("DB CREATED SUCCESSFULLY")
    return True



