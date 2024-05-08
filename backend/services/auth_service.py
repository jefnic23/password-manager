from datetime import datetime, timedelta, timezone

from config import Settings
from exceptions import credentials_exception
from fastapi import HTTPException
from jose import JWTError, jwt
from models.user import User
from passlib.context import CryptContext
from services.users_service import UsersService
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import select
from models.refresh_token import RefreshToken


class AuthService:
    PASSWORD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def __init__(
        self, users_service: UsersService, settings: Settings, session: AsyncSession
    ):
        self.users_service = users_service
        self.settings = settings
        self.session = session

    def generate_token(self, expiry_minutes: int, sub: str) -> str:
        exp = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
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
        if not AuthService.verify_password(secret=password, hash=user.password):
            return False
        return user

    async def verify_refresh_token(
        self, token: str, exception: HTTPException = credentials_exception
    ) -> dict[str, any]:
        payload = self.verify_token(token)
        email = payload.get("sub")
        exp = payload.get("exp")
        statement = (
            select(RefreshToken)
            .where(RefreshToken.user.email == email)
            .where(RefreshToken.expiry_time == exp)
        )
        results = await self.session.exec(statement=statement)
        if not results.one_or_none():
            raise exception
        return payload

    def verify_token(
        self, token: str, exception: HTTPException = credentials_exception
    ) -> dict[str, any]:
        try:
            payload = jwt.decode(token, self.settings.SECRET_KEY, algorithms=["HS256"])
            email: str | None = payload.get("sub")
            if email is None:
                raise exception
        except JWTError:
            raise exception
        return payload

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
