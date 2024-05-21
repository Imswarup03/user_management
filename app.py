from flask import Flask, jsonify,request
import os
from configs.config import Config
from database.orm import db
import logging


PORT = os.environ.get('PORT')

def create_app():
    # logging.basicConfig(filename='record.log', level=logging.DEBUG)
    from controller.user_controller import bcrypt
    from blueprints.user_blueprint import user_bp
    app = Flask(__name__)
    #Here I am configuring the app from configuration
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

