from flask import jsonify, Blueprint,request,make_response
from models.user_models import User,db
from flask_bcrypt import Bcrypt
from functools import wraps
from pydantic import BaseModel,EmailStr, ValidationError, field_validator

bcrypt= Bcrypt()
user_controller = Blueprint('user_controller', __name__)



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

class SignIn(BaseModel):
    username : str
    email: str
    phone_number: str
    password : str

    @field_validator('username', 'email', 'phone_number',mode='befpre')
    def check_one_identifier(cls, v, values, field, **kwargs):
        if not v and not any(values.get(f) for f in ['username', 'email', 'phone_number'] if f != field.name):
            raise ValueError('You must provide either a username, email, or phone number.')
        return v
#registration
@user_controller.route('/register',methods=['POST'])
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
                    return jsonify({'error': 'Phone number already exists'}), 400
                
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



@user_controller.route('/login',methods=['GET','POST'])
def login():
    data = request.get_json()
    sign_input = SignIn(**data)

    print(sign_input)

    return jsonify({
        "message":"Success"
    }),200



















# @user_controller.route('/login',methods=['GET',"POST"])
# def login():
#     if request.method=='POST':
#         data = request.get_json()
#         username = data.get('username',None)
#         email = data.get('email',None)
#         phone_number= data.get('phone_number',None)
#         password = data.get('password')

#         if username or email or phone_number and password:
#             pass
            
#         else:
#             response = make_response("Please provide your email or phone number or username")


#     else:
#         "Show the login form"
#         return "Show the Login"


# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
#         # jwt is passed in the request header
#         if 'x-access-token' in request.headers:
#             token = request.headers['x-access-token']
#         # return 401 if token is not passed
#         if not token:
#             return jsonify({'message' : 'Token is missing !!'}), 401

#         try:
#             # decoding the payload to fetch the stored details
#             data = jwt.decode(token, app.config['SECRET_KEY'])
#             current_user = User.query\
#                 .filter_by(public_id = data['public_id'])\
#                 .first()
#         except:
#             return jsonify({
#                 'message' : 'Token is invalid !!'
#             }), 401
#         # returns the current logged in users context to the routes
#         return  f(current_user, *args, **kwargs)

#     return decorated