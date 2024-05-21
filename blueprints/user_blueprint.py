from flask import Blueprint

user_bp = Blueprint('user',__name__,url_prefix='/api/v1/user')
from controller.user_controller import user_controller

user_bp.register_blueprint(user_controller)