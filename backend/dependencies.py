from typing import Annotated

from config import settings
from database import db
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from models.user import User
from services.auth_service import AuthService
from services.services_service import ServicesService
from services.users_service import UsersService
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="token")


async def get_services_service(
    session: AsyncSession = Depends(db.get_async_session),
) -> ServicesService:
    return ServicesService(session=session)


async def get_users_service(
    session: AsyncSession = Depends(db.get_async_session),
) -> UsersService:
    return UsersService(session=session)


async def get_auth_service(
    users_service: UsersService = Depends(get_users_service),
) -> AuthService:
    return AuthService(users_service=users_service)


async def get_current_user(
    token: Annotated[str, Depends(OAUTH2_SCHEME)],
    users_service: UsersService = Depends(get_users_service),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await users_service.get_user(email=email)
    if user is None:
        raise credentials_exception
    return user
