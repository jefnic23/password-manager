from dependencies import CURRENT_USER_DEPENDENCY
from fastapi import APIRouter

router = APIRouter()


@router.get("/users")
async def get_user(current_user: CURRENT_USER_DEPENDENCY) -> str:
    return current_user.email
