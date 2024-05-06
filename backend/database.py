from config import Settings, get_settings
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession


def get_async_engine(settings: Settings = Depends(get_settings)) -> AsyncEngine:
    return create_async_engine(
        settings.DATABASE_URL,
        echo=True,
        future=True,
    )


async def init_db(engine: AsyncEngine = Depends(get_async_engine)) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


async def get_async_session(
    engine: AsyncEngine = Depends(get_async_engine),
) -> AsyncSession:
    session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session() as async_session:
        yield async_session
