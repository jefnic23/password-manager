import secrets
import string

from cryptography.fernet import Fernet
from flask import current_app


class Password():
    def __init__(self, password=None):
        self.password = password
        self.length = secrets.SystemRandom().randrange(16, 24)
        self.chars = [*string.ascii_letters,
                      *string.digits,
                      *["!", "*", "@", "#", "$", "%", "&", "+", "="]]
        self.fernet = Fernet(current_app.config.get('SECRET_KEY'))
        self.generate_password()

    def generate_password(self):
        '''Generates a random password.'''
        if not self.password:
            while True:
                self.password = ''.join(secrets.choice(self.chars) for _ in range(self.length))
                if (any(c.islower() for c in self.password)
                        and any(c.isupper() for c in self.password)
                        and sum(c.isdigit() for c in self.password) >= 2
                        and sum(c in string.punctuation for c in self.password) >= 1):
                    break
        return self.password

    def encrypt(self):
        '''Encrypts the password using the secret key.'''
        return self.fernet.encrypt(self.password.encode())

    def decrypt(self):
        '''Decrypts the password using the secret key.'''
        return self.fernet.decrypt(self.password).decode()
