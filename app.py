from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
#init
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') 

#Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#init DB
db = SQLAlchemy(app)

#init ma
ma = Marshmallow(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    host_url = db.Column(db.String(350), nullable=True)

    def __init__(self, username, password, host_url):
        self.username = username
        self.password = password
        self.host_url = host_url

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'password', 'host_url')
#init Schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

#decorator for authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated
    

@app.route('/users')
def get_users():
    users = User.query.all()
    return users_schema.jsonify(users)

@app.route('/getUser/<id>')
@token_required
def getUser(current_user,id):
    user = User.query.get(id);
    return user_schema.jsonify(user)

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=14)}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/signup', methods=['POST'])
def create_user():
    password = generate_password_hash(request.json['password'])
    username = request.json['username']
    host_url = request.json['host_url']

    new_user = User(username, password, host_url)
    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)

# @app.route('/unprotected')
# def unprotected():
#     return ''

# @app.route('/protected')
# def protected():
#     return ''

# @app.route('/login')
# def login():
#     auth = request.authorization

#     if auth and auth.password == 'password':
#         return 'Logged in'
#     return make_response('Could not Verify', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})