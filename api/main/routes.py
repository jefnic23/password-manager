from cryptography.fernet import Fernet
from flask import current_app, request

from api.app import db
from api.auth.decorators import login_required
from api.main import bp
from api.models import *
from api.password import Password


@bp.route('services', methods=['GET'])
@login_required
def get_services(current_user):
    '''Returns a list of services for the current user.'''
    services = db.session.execute(db.select(Service).filter_by(user_id=current_user.id).order_by('service')).scalars()
    return {'services': [service.service for service in services]}, 200


@bp.route('services/<service>', methods=['GET'])
@login_required
def get_service(current_user, service):
    '''Returns the password for the specified service.'''
    service = db.session.execute(db.select(Service).filter_by(service=service, user_id=current_user.id)).scalar_one_or_none()
    if not service:
        return {'message': 'Service does not exist.'}, 404
    password = Password(password=service.password).decrypt()
    return {'service': service.service, 'password': password}, 200


@bp.route('services', methods=['POST'])
@login_required
def create_service(current_user):
    '''Creates a new service for the current user.'''
    post_data = request.get_json()
    service = post_data.get('service')
    service_exists = db.session.execute(db.select(Service).filter_by(service=service, user_id=current_user.id)).scalar_one_or_none()
    if service_exists:
        return {'message': 'Service already exists.'}, 400    
    password = Password().encrypt()
    new_service = Service(service=service, password=password, user_id=current_user.id)
    db.session.add(new_service)
    db.session.commit()
    return {'message': 'Service created successfully.'}, 201


@bp.route('services/<service>', methods=['PUT'])
@login_required
def update_service(current_user, service):
    '''Updates the password for the specified service.'''
    service = db.session.execute(db.select(Service).filter_by(service=service, user_id=current_user.id)).scalar_one_or_none()
    if not service:
        return {'message': 'Service does not exist.'}, 404
    new_password = Password().encrypt()
    service.password = new_password
    db.session.commit()
    return {'message': 'Service updated successfully.'}, 200


@bp.route('services/<service>', methods=['DELETE'])
@login_required
def delete_service(current_user, service):
    '''Deletes the specified service.'''
    service = db.session.execute(db.select(Service).filter_by(service=service, user_id=current_user.id)).scalar_one_or_none()
    if not service:
        return {'message': 'Service does not exist.'}, 404
    db.session.delete(service)
    db.session.commit()
    return {'message': 'Service deleted successfully.'}, 200
