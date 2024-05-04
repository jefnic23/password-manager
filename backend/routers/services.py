from typing import Annotated

from dependencies import get_current_user, get_services_service
from fastapi import APIRouter, Depends, HTTPException
from models.user import User
from services.services_service import ServicesService
from starlette import status

router = APIRouter()


@router.get("/services")
async def get_all_services(
    current_user: Annotated[User, Depends(get_current_user)],
    services_service: Annotated[ServicesService, Depends(get_services_service)],
) -> list[str]:
    return await services_service.get_all(user_id=current_user.id)


@router.get("/services/{name}")
async def get_service(
    current_user: Annotated[User, Depends(get_current_user)],
    services_service: Annotated[ServicesService, Depends(get_services_service)],
    name: str,
) -> str:
    encrypted_password = await services_service.get(user_id=current_user.id, name=name)
    if not encrypted_password:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Password not found",
        )
    return services_service.decrypt_password(encrypted_password)
