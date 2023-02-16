from passlib.hash import pbkdf2_sha256
import jwt, datetime
from api.app import db
from flask import current_app

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password)

    def set_password(self, password):
        self.password = password

    def generate_token(self, claim, expires_in):
        return jwt.encode(
            {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in),
                'iat': datetime.datetime.utcnow(),
                claim: self.id
            },
            current_app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )

    @staticmethod
    def verify_token(token, claim):
        try:
            return jwt.decode(token, current_app.config.get('SECRET_KEY'), algorithms=['HS256'])[claim]
        except jwt.ExpiredSignatureError:
            return 'Your session has expired. Please log in again.'
        except:
            return 'An error occurred during login. Please try again.'
        # return User.query.get(id)

class Service(db.Model):
    __tablename__ = "services"
    service = db.Column(db.String(), primary_key=True, unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def set_password(self, password):
        self.password = password