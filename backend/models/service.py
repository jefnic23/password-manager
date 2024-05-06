from models.user import User
from sqlmodel import Field, Relationship, SQLModel


class Service(SQLModel, table=True):
    __tablename__ = "services"

    id: int = Field(primary_key=True)
    name: str = Field(unique=True)
    password: str

    user_id: int = Field(foreign_key="users.id")
    user: User = Relationship(back_populates="services")
