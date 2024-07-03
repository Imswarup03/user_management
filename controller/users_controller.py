from flask import Blueprint,request,jsonify
import json
from models.user_models import User
from flask_jwt_extended import get_current_user,get_jwt_identity,jwt_required
# from auth_controller import isAdmin


user_controller= Blueprint('user_controller', __name__)


# @jwt_required
def isAdmin(current_user):
    try:
        # current_user= get_current_user(:
        user =User.query.filter_by(username= current_user['name']).first()
        if user.role =="Admin":
            return True
        return False
    except Exception as e:
        return False
    



@user_controller.route('/all',methods=['GET'])

@jwt_required(locations=['headers','cookies'])
def get_all_users():
    token = request.headers.get('Authorization')
    current_user= get_jwt_identity()
    if current_user:
        isAdmin_decide= isAdmin(current_user)
        print("User is ", isAdmin_decide)
        if isAdmin_decide:
            users = User.query.all()
            users_data = []
            for user in users:
                users_data.append({'id': user.id, 'username': user.username, 'email': user.email,'phoneNumber':user.phone_number, 'role':user.role, 'isBlocked':user.isBlocked})
                
            # print ("users", users_data)

            return jsonify({
                "statusCode":200,
                "message":users_data
            }),200
        return jsonify({
                "statusCode":401,
                "message":"You are not authorized to access this resource"
            }),401
    return jsonify({
        "statusCode":400,
        "message":'token is not present'
    }),400



@user_controller.route('/update-profile/<int:id>', methods= ['GET'])
@jwt_required(locations=['headers','cookies'])
def update_profile(id : int):
    get_current_user()
    pass





