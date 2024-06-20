from flask import jsonify, Blueprint,request,make_response
import pytz
from datetime import  datetime
from models.user_models import User,db
from flask_bcrypt import Bcrypt
from functools import wraps
from pydantic import BaseModel,EmailStr, ValidationError
from flask_jwt_extended import JWTManager , create_access_token,create_refresh_token,jwt_required,get_jwt_identity,get_current_user, set_access_cookies, decode_token, set_refresh_cookies
from configs.email_config import send_email
import random
import asyncio
import os
import time


jwt= JWTManager()



bcrypt= Bcrypt()
auth = Blueprint('auth', __name__)


@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({
        'message': 'Request does not contain an access token.',
        'error': 'authorization_required'
    }), 401

@jwt.invalid_token_loader
def invalid_token_response(callback):
    return jsonify({
        'messge': 'Signature verification failed',
        'error': 'invalid_token'
    }), 422
@jwt.expired_token_loader
def expired_token_response(jwt_header, jwt_data):
    return jsonify({
        'message':"Please relogin again",
        'error':'Expired Token'
    }),500


class UserInput(BaseModel):
    username: str
    firstname: str
    lastname: str
    email: EmailStr
    phone_number: int
    password: str
    confirm_password: str
    role: str = None 
    isBlocked : bool = False
    address: str = None




#registration
@auth.route('/register',methods=['POST'])
def register():
    'registration of user'
    try:
        data= request.get_json()
        # username= data.get('username')
        # name = data.get('name')
        # email = data.get('email')
        # password = data.get('password')
        # confirm_password = data.get('confirm_password')
        # phone_number = data.get('phone_number')
        # isAdmin= data.get('isAdmin',False)
        user_input = UserInput(**data)
        firstname = user_input.firstname
        lastname= user_input.lastname
        username= user_input.username
        email = user_input.email
        password = user_input.password
        confirm_password = user_input.confirm_password
        phone_number = user_input.phone_number
        role= user_input.role 

        if not firstname or not username or not email or not phone_number or not password or not confirm_password:
                    response = jsonify({
                        "message":"Missing Data",
                        "status_code":400
                    })
                    return response,400
            
        elif username and email and phone_number and password and confirm_password and password != confirm_password:
                response = {
                    "message":"password and confirm password must be same",   
                }
                return jsonify(response),400
            
        elif username and email and phone_number and password and confirm_password and password == confirm_password:
                if User.query.filter_by(username=username).first():
                    return jsonify({'error': 'Username already exists'}), 400
                elif User.query.filter_by(email=email).first():
                    return jsonify({'error': 'Email already exists'}), 400
                elif User.query.filter_by(phone_number=phone_number).first():
                    return jsonify({'error': 'Phone number already exists, try with a different phone number'}), 400
                
                else:
                    # using only bcrypt
                    # generate_salt = bc.gensalt(14)
                    # bytes_password = password.encode('utf-8')
                    # hashed_password= bc.hashpw(bytes_password,generate_salt)
                    #using flask_bcrypt
                    # hashed_password = bcrypt.generate_password_hash('password').decode('utf-8') // doing hasing in model itslef
                    # after hasing we can store it in DB
                    user = User(
                            username=username,
                            firstname=firstname,
                            lastname=lastname,
                            email=email,
                            phone_number=phone_number,
                            password=password,
                            role = role
                            )
                    db.session.add(user)
                    print("user",user)
                    db.session.commit()

                    response = jsonify({
                        "message":"User Has been added successfully", 
                        "status_code":201
                        }),201
                    return response
    except ValidationError  as e:
        errors = e.errors()
        print(errors[0]['msg'],type(errors))
        return jsonify({"message":errors[0]['msg'], "status_code": 400}), 400
    except Exception as e:
        print ("some error occured ", e)
        return jsonify({"message":"something went wrong", "status_code": 500}), 500



@auth.route('/login',methods=['POST'])
def login():
    "login method for user"
    try:
        sign_input = request.get_json()
        # print("sign_input",sign_input)
        if not sign_input["identifier"]:
            return jsonify({
                "message":"Missing Data. Atleast provide username or email"
            }), 400
        
        if  sign_input["identifier"] and sign_input["password"]:
            identity = sign_input["identifier"]
            user = User.query.filter_by(username = identity).first() or  User.query.filter_by(email = identity).first() or  User.query.filter_by(phone_number = identity).first()
            if not user:
                return jsonify({
                    "message":"user doesn't exist"
                }),400
            password= sign_input['password']
            hashed_password = user.password
            check_password_hash = bcrypt.check_password_hash(hashed_password, password )
            # print(user.refreshToken)

            if check_password_hash:
                refresh_token = create_refresh_token(user.username)
                access_token= create_access_token({"name":user.username,"id":user.id}) # token expiry sets at JWT_TOKEN_EXPIRES in config.py
                user.refreshToken = refresh_token
                db.session.commit()
                response =  jsonify(
                    {
                        "message":"logged in successfully",
                        "tokens":{
                        "access_token":access_token,
                        "refresh_token":refresh_token
                        }
                    }
                    )
                
                response.set_cookie(
                    'refreshToken', refresh_token, max_age=72*60*60, secure= True, httponly=True
                    )
                # set_refresh_cookies(response,refresh_token,max_age=72*60*60, secure= True, httponly=True)

                return response,200
            else:
                return jsonify({
                    "message": "Invalid username or password."
                }), 400
        else:
            return jsonify({
                "message": "Please provide both username and password."
            }), 400
    except Exception as e:
        return jsonify ("something went wrong ",e), 500
    




@auth.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        
        print("request", request.headers)
        # Get the identity of the current user
        current_user = get_jwt_identity()
        print("logging out user:", current_user)

        # Get the refresh token from the cookie
        refresh_token = request.cookies.get('refreshToken')
        if not refresh_token:
            return jsonify({
                "message": "Refresh token not found.",
                "statusCode": 400
            }), 400

        # If using a database to store refresh tokens, remove the refresh token entry for the user
        user = User.query.filter_by(username=current_user['name']).first()
        if user:
            user.refreshToken = None  # Clear the refresh token in the database
            db.session.commit()

        # Clear the refresh token cookie
        response = jsonify({
            "message": 'User logged out successfully',
            "statusCode": 200
        })
        response.delete_cookie('refreshToken')

        return response, 200

    except Exception as e:
        return jsonify({
            "message": "An error occurred while logging out.",
            "statusCode": 500,
            "error": str(e)
        }), 500


@auth.route('/refresh',methods= ['GET'])
def handle_refresh_token():
    try:
        refreshToken = request.cookies.get('refreshToken','')
        
        # print("cookies",refreshToken)
        if not refreshToken:
            return jsonify({
                "error":"No Valid Token present",
                "message":"error"
            }),400
        # refreshToken= cookies.refreshToken
        # current_user= get_jwt_identity()
        # print("current_user==========",current_user)
        user = User.query.filter_by(refreshToken=refreshToken).first()
        print("user",user)
        if not user:
            return jsonify({
                "error":"No Valid Token present",
                "message":"error"
            }),400
        access_token= create_access_token({"name":user.username,"id":user.id})
        return jsonify({
            "access_token":access_token
        })
    except Exception as e:
        return jsonify({
            "error": "An error occurred",
            "message": str(e)
        }), 500
    



@auth.route('/forgotpassword',methods=['GET','POST'])
def forgot_password():
    try:
        identity = request.json.get('identifier')
        print('identity', identity)
        user = User.query.filter_by(username = identity).first() or  User.query.filter_by(email = identity).first() or  User.query.filter_by(phone_number = identity).first()
        if not user:
            return jsonify({
                'message':"User doesn't exist",
                "statusCode":401
            }),401
        
        #send email to the user using a link with accessToken (Valid for 10 mins)
        #if user click on the link we will use that accessToken to verify the user
        #after verification user will enter password and confirm password 
        #we will update the password and save in th db
        #user can login again
        else:
            otp = random.randint(10000,999999)
            print("OTP",otp)
            username = user.username
            email = user.email
            set_access_cookies= create_access_token({'email':email})
            print("cookies", set_access_cookies)
            subject = 'Verification for Reset password'
            body = f"Dear {user.firstname} {user.lastname}. Your OTP is {otp}. Use this to verify your identity."
            send_email_user= send_email(email,subject,body)
            if send_email_user:
                response = jsonify({
                    "message": "OTP sent Successfully",
                    "statusCode":200
                })

                response.set_cookie(
                    'access_cookies',set_access_cookies , max_age=10*60, secure= False, httponly=False
                    )
            secret_key = os.environ.get('SECRET_KEY')
            set_password_reset = user.set_password_reset_expiration()
            set_otp= user.generate_and_store_otp(otp, 10, secret_key)
            print("set_otp",set_otp, "set_password_reset",set_password_reset)
            return response,200
    except Exception as e:
        print(e)
        return jsonify({
            "message": "Something Went Wrong",
            "statusCode": 500
        }),500

@auth.route('/verifyotp', methods= ['POST'])
def verify_otp():
    try:
        access_cookies = request.cookies.get('access_cookies', None)
        print("requests=====>", request)
        print("access_cookies", access_cookies) 
        otp= request.json.get('otp',None)
        secret_key = os.environ.get('SECRET_KEY')
        salt = 10
        combined = f'{otp}{salt}{secret_key}'
        # hashed_otp = bcrypt.generate_password_hash(combined,10).decode('utf-8')
        print("OTP",otp)
        if access_cookies and otp:
            decoded_token = decode_token(access_cookies)
            user_email = decoded_token['sub'].get('email')
            print("decoded",user_email)
            user= User.query.filter_by(email=user_email).first()
            print("user", user)
            stored_hashed_otp= user.otp
            otpExpiresAt = user.otpExpiresAt
            current_time = int(time.time())

            if otpExpiresAt > current_time:
                if verify_otp(stored_hashed_otp, combined):
                    response = jsonify({
                        'message':"sucess",
                        "statusCode":200
                    })
                    # response.delete_cookie('access_cookies')
                    user.otpExpiresAt = None
                    # user.resetPasswordExpiresAt = None
                    user.otp= None
                    return response
                else:
                    return jsonify({
                        'message':"OTP is Invalid",
                        "statusCode":400
                    }),400
            else:
                return jsonify({
                        'message':"OTP is Expired",
                        "statusCode":400
                    }),400
        else:
            return jsonify({
                'message':"OTP is Invalid Try Agin Later",
                "statusCode":403
            }),403
    except Exception as e:
        print(e)
        return jsonify({
                'message':"failed",
                "statusCode":500
            }),500



@auth.route('/reset-password', methods=['POST'])
def reset_password():
    ''' reset the password'''
    # 19th June
    try:
        access_cookie = request.cookies.get('access_cookies', '')
        print("access_cookie", access_cookie)
        if access_cookie:
            try:
                decoded_token = decode_token(access_cookie)
                print("decoded_toke", decoded_token)
            except Exception as e:
                return jsonify({
                    'message': "Please sign in again",
                    'statusCode': 401
                }), 401

            email = decoded_token['sub'].get('email')
            user = User.query.filter_by(email=email).first()

            if not user:
                return jsonify({
                    'message': "User not found",
                    'statusCode': 404
                }), 404

            password = request.json.get('password','')
            confirm_password = request.json.get('confirm_password','')
            print('password', password)
            print('CONFIMR PASSWORD', confirm_password)
            if password and confirm_password:
                if password == confirm_password:
                    print("password matched")
                    set_password = user.update_password(password, confirm_password)
                    response = jsonify({
                        "message": "Your password has been updated successfully, login again",
                        "statusCode": 200
                    })
                    response.delete_cookie('access_cookies')
                    user.resetPasswordExpiresAt = None
                    db.session.commit()
                    return response, 200
                else:
                    return jsonify({
                        "message": "Passwords must match",
                        "statusCode": 400
                    }), 400
            else:
                return jsonify({
                    "message": "You must provide password and confirm password",
                    'statusCode': 400
                }), 400

    except Exception as e:
        print(e)
        return jsonify({
            'message': "Something went wrong",
            "statusCode": 500
        }), 500

























def verify_otp(stored_hashed_otp, new_otp):
    check = bcrypt.check_password_hash(stored_hashed_otp, new_otp)
    print('check', check)
    return check