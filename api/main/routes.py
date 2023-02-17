from flask import current_app, request

from api.app import db
from api.auth.decorators import login_required
from api.emails import send_password_reset_email
from api.main import bp
from api.models import *
from cryptography.fernet import Fernet


@bp.route('services', methods=['GET'])
@login_required
def get_services(current_user):
    services = db.session.execute(db.select(Service).filter_by(user_id=current_user.id).order_by('service')).scalars()
    return {'services': [service.service for service in services]}, 200


@bp.route('services', methods=['POST'])
@login_required
def create_service(current_user):
    post_data = request.get_json()
    service = post_data.get('service')
    service_exists = db.session.execute(db.select(Service).filter_by(service=service, user_id=user_id)).scalar_one_or_none()
    if service_exists:
        return {'message': 'Service already exists.'}, 400    
    password = Password()
    fernet = Fernet(current_app.config.get('SECRET_KEY'))
    enc_password = fernet.encrypt(password.encode())
    new_service = Service(service=service, password=enc_password, user_id=current_user.id)
    db.session.add(new_service)
    db.session.commit()
    return {'message': 'Service created successfully.'}, 201

# @app.route('/password-manager', methods=['GET', 'POST'])
# @login_required
# def pswd_manager():
#     if current_user.is_anonymous:
#         flash('Please login.', 'danger')
#         return redirect(url_for('index'))
#     create_form = CreateServiceForm()
#     select_form = SelectServiceForm()
#     select_form.services.choices = [("", "")] + [(service.service, service.service) for service in Service.query.filter_by(user_id=current_user.id).order_by('service').all()]
#     if select_form.validate_on_submit() and select_form.services.data:
#         service_name = Service.query.filter_by(service=select_form.services.data, user_id=current_user.id).first()
#         password = service_name.password
#         dec_password = fernet.decrypt(password).decode()
#         flash('Password has been copied to your clipboard.', 'success')
#         return render_template('password-manager.html', select_form=select_form, create_form=create_form, password=dec_password)
#     if create_form.validate_on_submit():
#         service_name = create_form.service.data
#         password = generate_password()
#         enc_password = fernet.encrypt(password.encode())
#         user_id = User.query.filter_by(id=current_user.id).first()
#         service_exists = Service.query.filter_by(service=service_name, user_id=current_user.id).first()
#         if service_exists:
#             service_exists.set_password(enc_password)
#             db.session.add(service_exists)
#             db.session.commit()
#             flash('Password changed.', 'success')
#             return redirect(url_for('pswd_manager'))
#         service = Service(service=service_name, password=enc_password, user_id=user_id.id)
#         db.session.add(service)
#         db.session.commit()
#         flash('Password created and stored.', 'success')
#         return redirect(url_for('pswd_manager'))
#     return render_template('password-manager.html', select_form=select_form, create_form=create_form)
