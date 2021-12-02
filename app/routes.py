from flask import render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, current_user, logout_user
from flask_bootstrap import Bootstrap
from cryptography.fernet import Fernet
from wtform_fields import *
from models import *
from password_generator import generate_password
from pandas.io import clipboard
from app.email import send_password_reset_email
from app import app

bootstrap = Bootstrap(app)
fernet = Fernet(app.config['SECRET_KEY'].encode())
login = LoginManager(app)
login.init_app(app)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

# routes

@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('pswd_manager'))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user_object = User.query.filter_by(username=login_form.username.data).first()
        login_user(user_object, remember=login_form.remember_me.data)
        return redirect(url_for('pswd_manager'))
    return render_template('index.html', form=login_form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    reg_form = RegistrationForm()
    if reg_form.validate_on_submit():
        username = reg_form.username.data
        password = reg_form.password.data
        email = reg_form.email.data
        hashed_pswd = pbkdf2_sha256.hash(password)
        user = User(username=username, password=hashed_pswd, email=email)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully. Please login.', 'success')
        return redirect(url_for('pswd_manager'))
    return render_template('register.html', form=reg_form)

@app.route('/logout', methods=['GET'])
def logout():
    if current_user.is_anonymous:
        return redirect(url_for("index"))
    logout_user()
    flash("You have logged out successfully.", "success")
    return redirect(url_for("index"))

@app.route("/reset_password_request", methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash("Check your email for instructions on how to reset your password.", 'info')
        return redirect(url_for('login'))
    return render_template("reset_password_request.html", form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        hashed_pswd = pbkdf2_sha256.hash(password)
        user.set_password(hashed_pswd)
        db.session.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/password-manager', methods=['GET', 'POST'])
def pswd_manager():
    if current_user.is_anonymous:
        return redirect(url_for('index'))
    create_form = CreateServiceForm()
    select_form = SelectServiceForm()
    select_form.services.choices = [("", "")] + [(service.service, service.service) for service in Service.query.filter_by(user_id=current_user.id).all()]
    return render_template('password-manager.html', select_form=select_form, create_form=create_form)

@app.route('/create-password', methods=['POST'])
def create_password():
    if current_user.is_anonymous:
        return redirect(url_for('index'))
    select_form = SelectServiceForm()
    create_form = CreateServiceForm()
    if create_form.validate_on_submit():
        service_name = create_form.service.data
        password = generate_password()
        enc_password = fernet.encrypt(password.encode())
        user_id = User.query.filter_by(id=current_user.id).first()
        service = Service(service=service_name, password=enc_password, user_id=user_id.id)
        db.session.add(service)
        db.session.commit()
        flash('Password created and stored.', 'success')
        return redirect(url_for('pswd_manager'))
    return render_template('password-manager.html', select_form=select_form, create_form=create_form)

@app.route('/retrieve-password', methods=['GET', 'POST'])
def retrieve_password():
    if current_user.is_anonymous:
        return redirect(url_for('index'))
    create_form = CreateServiceForm()
    select_form = SelectServiceForm()
    select_form.services.choices = [("", "")] + [(service.service, service.service) for service in Service.query.filter_by(user_id=current_user.id).all()]
    if select_form.validate_on_submit():
        service_name = Service.query.filter_by(service=select_form.services.data, user_id=current_user.id).first()
        password = service_name.password
        dec_password = fernet.decrypt(password).decode()
        clipboard.copy(dec_password)
        flash('Password has been copied to your clipboard.', 'success')
        return redirect(url_for('pswd_manager'))
    return render_template('password-manager.html', select_form=select_form, create_form=create_form)

if __name__ == '__main__':
    app.run()