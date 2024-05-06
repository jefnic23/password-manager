from config import Settings
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession


class Database:
    def __init__(self, settings: Settings):
        self.engine: AsyncEngine = create_async_engine(
            settings.DATABASE_URL,
            echo=True,
            future=True,
        )
        self.session: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )
