from functools import wraps

from api.models import User
from flask import abort, request


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        try:
            id = User.verify_token(token, 'sub')
            current_user = User.query.get(id)
            # do something if current_user fails?
        except Exception as e:
            return {
                'message': 'Something went wrong.',
                'error': str(e)
            }, 500

        return f(current_user, *args, **kwargs)

    return decorated
