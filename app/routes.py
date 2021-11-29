from flask import render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from wtform_fields import *
from models import *
from password_generator import generate_password
from app import app

login = LoginManager(app)
login.init_app(app)

# routes

@app.route('/')
def index():
    # place reg_form and login_form here
    return render_template('index.html')