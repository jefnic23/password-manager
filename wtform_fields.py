from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, BooleanField
from wtforms.fields.simple import SubmitField
from wtforms.validators import DataRequired, InputRequired, Length, EqualTo, ValidationError, Email
from passlib.hash import pbkdf2_sha256
from models import * 


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(message="Username required")])
    password = PasswordField('Password', validators=[InputRequired(message="Password required")])
    remember_me = BooleanField('Remember me')
    submit_button = SubmitField('Login')


class RegistrationForm(FlaskForm):
    username = StringField('Username', 
        validators=[InputRequired(message="Username required"), 
        Length(min=4, max=25, message="Username must be between 4 and 25 characters")])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password',
        validators=[InputRequired(message="Password required"), 
        Length(min=8, message="Password must be at least 8 characters")])
    confirm_pswd = PasswordField('Confirm password',
        validators=[InputRequired(message="Password required"), 
        EqualTo("password", message="Passwords must match")])
    submit_button = SubmitField("Register")

    def validate_username(self, username):
        user_object = User.query.filter_by(username=username.data).first()
        if user_object:
            raise ValidationError("Username already exists.")

    def validate_email(self, email):
        user_object = User.query.filter_by(email=email.data).first()
        if user_object:
            raise ValidationError("An account with this email already exists.")


class ResetPasswordRequestForm(FlaskForm):
    email = StringField("Enter your email", validators=[DataRequired(), Email()])
    submit_button = SubmitField("Request Password Reset")


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New password',
        validators=[InputRequired(message="Password required"), 
        Length(min=8, message="Password must be at least 8 characters")])
    confirm_pswd = PasswordField('Confirm new password',
        validators=[InputRequired(message="Password required"), 
        EqualTo("password", message="Passwords must match")])
    submit_button = SubmitField("Submit new password")


class CreateServiceForm(FlaskForm):
    service = StringField("Enter the name of the service you'd like to create a password for", validators=[InputRequired(message='Service name required')])
    submit_create = SubmitField("Generate password")


class SelectServiceForm(FlaskForm):
    services = SelectField("Select a service to get its password")
    submit_select = SubmitField("Retrieve password")