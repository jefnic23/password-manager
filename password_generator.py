import string, secrets

chars = [*string.ascii_lowercase,
         *string.ascii_uppercase,
         *string.digits,
         *string.punctuation
         ]

def generate_password(chars=chars):
    length = secrets.SystemRandom().randrange(12, 16)
    while True:
        password = ''.join(secrets.choice(chars) for _ in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 2
                and sum(c in string.punctuation for c in password) >= 1):
            break
    return password