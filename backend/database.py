from typing import AsyncGenerator

from config import settings
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlmodel.ext.asyncio.session import AsyncSession

Base = declarative_base()


class Database:
    def __init__(self):
        self.engine: AsyncEngine = create_async_engine(
            settings.DATABASE_URL,
            echo=False,
            future=True,
        )
        self.session: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )

    async def get_async_session(self) -> AsyncGenerator[AsyncSession, None]:
        async with self.session() as async_session:
            yield async_session


db = Database()
