from datetime import datetime, timedelta, timezone

from config import Settings
from jose import jwt
from models.user import User
from passlib.context import CryptContext
from services.users_service import UsersService


class AuthService:
    PASSWORD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def __init__(self, users_service: UsersService, settings: Settings):
        self.users_service = users_service
        self.settings = settings

    def generate_access_token(self, sub: str) -> str:
        exp = datetime.now(timezone.utc) + timedelta(minutes=5)
        claims = {
            "exp": exp,
            "sub": sub,
        }

        return jwt.encode(
            claims=claims,
            key=self.settings.SECRET_KEY,
            algorithm="HS256",
        )

    async def authenticate_user(self, email: str, password: str) -> User | bool:
        user = await self.users_service.get_user(email=email)
        if not user:
            return False
        if not self.verify_password(secret=password, hash=user.password):
            return False
        return user

    @staticmethod
    def verify_password(
        secret: str, hash: str, password_context: CryptContext = PASSWORD_CONTEXT
    ) -> bool:
        return password_context.verify(secret=secret, hash=hash)

    @staticmethod
    def hash_password(
        secret: str, password_context: CryptContext = PASSWORD_CONTEXT
    ) -> str:
        return password_context.hash(secret=secret)
