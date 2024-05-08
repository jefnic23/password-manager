from typing import Annotated

from dependencies import AUTH_SERVICE_DEPENDENCY
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from schemas.token import Token
from starlette import status

router = APIRouter()


@router.post("/login")
async def get_access_token(
    auth_service: AUTH_SERVICE_DEPENDENCY,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = await auth_service.authenticate_user(
        email=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth_service.generate_token(expiry_minutes=5, sub=user.email)
    return Token(access_token=access_token, token_type="bearer")
