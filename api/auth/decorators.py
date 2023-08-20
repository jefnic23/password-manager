from functools import wraps

from api.models import User
from flask import abort, request


def login_required(func):
    '''Decorator to check if user is logged in.'''
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1]
        if not token:
            return {
                'message': 'Token is missing.'
            }, 401

        try:
            id = User.verify_token(token, 'sub')
            current_user = User.query.get(id)
            if current_user is None:
                return {
                    'message': 'User does not exist.'
                }, 404
        except Exception as e:
            return {
                'message': 'Something went wrong.',
                'error': str(e)
            }, 500

        return func(current_user, *args, **kwargs)

    return wrapper
