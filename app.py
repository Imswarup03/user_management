from flask import Flask
import os
from configs.config import Config
from controller.user_controller import bcrypt
from blueprints.user_blueprint import user_bp    
from database.settings import db


PORT = os.environ.get('PORT')

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config) 
    db.init_app(app)
    bcrypt.init_app(app)

    with app.app_context():
        db.create_all()

    app.register_blueprint(user_bp)

    return app

if __name__=="__main__":
    app= create_app()
    print(f"Flask server is running on http://localhost:{PORT}")
    app.run(debug=True,port= PORT)

