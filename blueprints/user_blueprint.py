from flask import Blueprint

user_bp = Blueprint('user_bp',__name__,url_prefix='/api/v1')

from controller.auth_controller import auth
from controller.users_controller import user_controller


user_bp.register_blueprint(auth,url_prefix ='/auth')
user_bp.register_blueprint(user_controller, url_prefix='/profile')




