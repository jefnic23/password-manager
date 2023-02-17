from flask import request

from api.app import db
from api.auth import bp
from api.models import User


@bp.route('/login', methods=['POST'])
def login():
    # validate the request data
    post_data = request.get_json()
    email = post_data.get('email')
    password = post_data.get('password')
    # get the user object using their email (unique to every user)  
    user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none()
    # try to authenticate the found user using their password
    if user and user.check_password(password):
        # generate the auth token
        auth_token = user.generate_token('sub', 600)
        if auth_token:
            response_object = {
                'status': 'success',
                'message': 'Successfully logged in.',
                'Authorization': auth_token
            }
            return response_object, 200
    # User does not exist. Therefore, we return an error message
    else:
        response_object = {
            'status': 'fail',
            'message': 'User does not exist.'
        }
        return response_object, 404

# @bp.route('/register', methods=['GET', 'POST'])
# def register():
#     reg_form = RegistrationForm()
#     if reg_form.validate_on_submit():
#         username = reg_form.username.data
#         password = reg_form.password.data
#         email = reg_form.email.data
#         hashed_pswd = pbkdf2_sha256.hash(password)
#         user = User(username=username, password=hashed_pswd, email=email)
#         db.session.add(user)
#         db.session.commit()
#         flash('Registered successfully. Please login.', 'success')
#         return redirect(url_for('pswd_manager'))
#     return render_template('register.html', form=reg_form)


# @bp.route('/logout', methods=['GET'])
# def logout():
#     if current_user.is_anonymous:
#         return redirect(url_for("index"))
#     logout_user()
#     flash("You have logged out successfully.", "success")
#     return redirect(url_for("index"))


# @bp.route("/reset_password_request", methods=['GET', 'POST'])
# def reset_password_request():
#     if current_user.is_authenticated:
#         return redirect(url_for('index'))
#     form = ResetPasswordRequestForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if user:
#             send_password_reset_email(user)
#         flash("Check your email for instructions on how to reset your password.", 'info')
#         return redirect(url_for('login'))
#     return render_template("reset_password_request.html", form=form)


# @bp.route('/reset_password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     if current_user.is_authenticated:
#         return redirect(url_for('index'))
#     user = User.verify_reset_password_token(token)
#     if not user:
#         return redirect(url_for('index'))
#     form = ResetPasswordForm()
#     if form.validate_on_submit():
#         password = form.password.data
#         hashed_pswd = pbkdf2_sha256.hash(password)
#         user.set_password(hashed_pswd)
#         db.session.commit()
#         flash('Your password has been reset.', 'success')
#         return redirect(url_for('login'))
#     return render_template('reset_password.html', form=form)
    