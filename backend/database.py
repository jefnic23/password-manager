from typing import Annotated, AsyncGenerator

from config import Settings, get_settings
from fastapi import Depends
from models.refresh_token import RefreshToken  # noqa: F401
from models.service import Service  # noqa: F401
from models.user import User  # noqa: F401
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession


class Database:
    def __init__(self, settings: Settings):
        self.engine: AsyncEngine = create_async_engine(
            settings.DATABASE_URL,
            echo=False,
            future=True,
        )
        self.async_session: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )


async def get_database(settings: Settings = Depends(get_settings)) -> Database:
    return Database(settings=settings)


async def get_async_session(
    database: Database = Depends(get_database),
) -> AsyncGenerator[AsyncSession, any]:
    async with database.async_session() as async_session:
        yield async_session


ASYNC_SESSION_DEPENDENCY = Annotated[AsyncSession, Depends(get_async_session)]
