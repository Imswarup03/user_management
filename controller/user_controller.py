from flask import jsonify, Blueprint,request,make_response
from models.user_models import User,db
from flask_bcrypt import Bcrypt
from functools import wraps


bcrypt= Bcrypt()
user_controller = Blueprint('user_controller', __name__)

#registration
@user_controller.route('/register',methods=['POST'])
def register():
    data= request.get_json()
    username= data.get('username')
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    phone_number = data.get('phone_number')

    print(data)
    if not name or not username or not email or not phone_number or not password or not confirm_password:
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
    
    elif username and email and phone_number and password or confirm_password and password == confirm_password:
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
            hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
            # after hasing we can store it in DB
            user = User(
                    username=username,
                    name=name,
                    email=email,
                    phone_number=phone_number,
                    password=hashed_password
                )
            db.session.add(user)
            print("user",user)
            db.session.commit()

            response = jsonify({
                "message":"User Has been added successfully", 
                "status_code":201
                }),201
            return response
        
@user_controller.route('/login',methods=['GET',"POST"])
def login():
    if request.method=='POST':
        data = request.get_json()
        username = data.get('username',None)
        email = data.get('email',None)
        phone_number= data.get('phone_number',None)
        password = data.get('password')

        if username or email or phone_number:
            pass
        else:
            response = make_response("Please provide your email or phone number or username")

    
    else:
        "Show the login form"
        return "Show the Login"
    

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users context to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated