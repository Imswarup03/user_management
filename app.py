from flask import Flask ,jsonify
from flask_cors import CORS
import os
# from configs.token import jwt_instance
from configs.config import Config
from controller.auth_controller import bcrypt, jwt
from blueprints.user_blueprint import user_bp
from database.settings import db
# from flask_wtf.csrf import CSRFProtect

PORT = os.environ.get('PORT')


def create_app():
    app = Flask(__name__)
    
    app.config.from_object(Config) 
    CORS(app,supports_credentials= True)
    # CSRFProtect(app)
    jwt.init_app(app)

    db.init_app(app)

    bcrypt.init_app(app)

    app.register_blueprint(user_bp)
    
    with app.app_context():
        db.create_all()

    
    
    return app

if __name__=="__main__":
    app= create_app()
    print(f"Flask server is running on http://localhost:{PORT}")
    @app.route('/',methods=['GET'])
    def index():
        return jsonify("Hello How are you"),200

    app.run(debug=True,port= PORT)
    
