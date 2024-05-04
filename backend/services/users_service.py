from models.user import User
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession


class UsersService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_user(self, email: str) -> User | None:
        statement = select(User).where(User.email == email)
        result = await self.session.exec(statement=statement)
        return result.one_or_none()
