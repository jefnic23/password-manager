from datetime import datetime, timedelta, timezone

from config import settings
from jose import jwt
from models.user import User
from passlib.context import CryptContext
from services.users_service import UsersService


class AuthService:
    def __init__(self, users_service: UsersService):
        self.users_service = users_service
        self.password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def verify_password(self, secret: str, hash: str) -> bool:
        return self.password_context.verify(secret=secret, hash=hash)

    def hash_password(self, secret) -> str:
        return self.password_context.hash(secret=secret)

    def generate_token(self, sub: str) -> str:
        exp = datetime.now(timezone.utc) + timedelta(minutes=5)
        claims = {
            "exp": exp,
            "sub": sub,
        }

        return jwt.encode(
            claims=claims,
            key=settings.SECRET_KEY,
            algorithm="HS256",
        )

    async def authenticate_user(self, email: str, password: str) -> User | bool:
        user = await self.users_service.get_user(email=email)
        if not user:
            return False
        if not self.verify_password(secret=password, hash=user.password):
            return False
        return user
