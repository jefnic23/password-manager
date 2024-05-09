from typing import Annotated

from exceptions import credentials_exception
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer

from config import SETTINGS_DEPENDENCY
from database import ASYNC_SESSION_DEPENDENCY
from models.user import User
from services.auth_service import AuthService
from services.refresh_tokens_service import RefreshTokensService
from services.services_service import ServicesService
from services.users_service import UsersService

OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl="login")
OAUTH_DEPENDENCY = Annotated[str, Depends(OAUTH2_SCHEME)]


async def get_services_service(
    session: ASYNC_SESSION_DEPENDENCY,
    settings: SETTINGS_DEPENDENCY,
) -> ServicesService:
    return ServicesService(session=session, settings=settings)


SERVICES_SERVICE_DEPENDENCY = Annotated[ServicesService, Depends(get_services_service)]


async def get_refresh_tokens_service(
    session: ASYNC_SESSION_DEPENDENCY,
) -> RefreshTokensService:
    return RefreshTokensService(session=session)


REFRESH_TOKENS_SERVICE_DEPENDENCY = Annotated[
    RefreshTokensService, Depends(get_refresh_tokens_service)
]


async def get_users_service(
    session: ASYNC_SESSION_DEPENDENCY,
) -> UsersService:
    return UsersService(session=session)


USERS_SERVICE_DEPENDENCY = Annotated[UsersService, Depends(get_users_service)]


async def get_auth_service(
    session: ASYNC_SESSION_DEPENDENCY,
    settings: SETTINGS_DEPENDENCY,
    users_service: USERS_SERVICE_DEPENDENCY,
    refresh_tokens_service: REFRESH_TOKENS_SERVICE_DEPENDENCY,
) -> AuthService:
    return AuthService(
        session=session,
        settings=settings,
        users_service=users_service,
        refresh_tokens_service=refresh_tokens_service,
    )


AUTH_SERVICE_DEPENDENCY = Annotated[AuthService, Depends(get_auth_service)]


async def get_current_user(
    token: OAUTH_DEPENDENCY,
    users_service: USERS_SERVICE_DEPENDENCY,
    auth_service: AUTH_SERVICE_DEPENDENCY,
) -> User:
    payload = auth_service.verify_token(token)
    user = await users_service.get_user_by_id(id=int(payload.get("sub")))
    if user is None:
        raise credentials_exception
    return user


CURRENT_USER_DEPENDENCY = Annotated[User, Depends(get_current_user)]
