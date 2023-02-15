from api.auth import bp
from api.models import User


@bp.route('/api/login', methods=['GET'])
def login():
    return ({'success': True, 'data': 'retard'})
    # if current_user.is_authenticated:
    #     return redirect(url_for('pswd_manager'))
    # login_form = LoginForm()
    # if login_form.validate_on_submit():
    #     user_object = User.query.filter_by(username=login_form.username.data).first()
    #     if not user_object or not user_object.check_password(login_form.password.data):
    #         flash('Invalid username or password', 'danger')
    #         return redirect(url_for('index'))
    #     login_user(user_object, remember=login_form.remember_me.data)
    #     return redirect(url_for('pswd_manager'))
    # return render_template('index.html', form=login_form)


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
    