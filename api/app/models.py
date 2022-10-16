from flask_login import UserMixin
from passlib.hash import pbkdf2_sha256
import jwt, time
from app import app, db

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password)

    def set_password(self, password):
        self.password = password

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode({'reset_password': self.id, 'exp': time() + expires_in}, app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

class Service(db.Model):
    __tablename__ = "services"
    service = db.Column(db.String(), primary_key=True, unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)

    def set_password(self, password):
        self.password = password