import datetime

from models.user import User
from sqlmodel import Field, Relationship, SQLModel


class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_tokens"

    id: int = Field(primary_key=True)
    token: str
    expiry_time: datetime

    user_id: int = Field(foreign_key="users.id", unique=True)
    user: User = Relationship(back_populates="refresh_token")
