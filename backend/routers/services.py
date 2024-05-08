from dependencies import CURRENT_USER_DEPENDENCY, SERVICES_SERVICE_DEPENDENCY
from fastapi import APIRouter, HTTPException
from starlette import status

router = APIRouter()


@router.get("/services")
async def get_all_services(
    current_user: CURRENT_USER_DEPENDENCY,
    services_service: SERVICES_SERVICE_DEPENDENCY,
) -> list[str]:
    return await services_service.get_all(user_id=current_user.id)


@router.get("/services/{name}")
async def get_service(
    current_user: CURRENT_USER_DEPENDENCY,
    services_service: SERVICES_SERVICE_DEPENDENCY,
    name: str,
) -> str:
    encrypted_password = await services_service.get(user_id=current_user.id, name=name)
    if not encrypted_password:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Password not found",
        )
    return services_service.decrypt_password(encrypted_password)
