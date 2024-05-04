import secrets
import string

from config import settings
from cryptography.fernet import Fernet
from models.service import Service
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession


class ServicesService:
    CHARS: list[str] = [
        *string.ascii_letters,
        *string.digits,
        *["!", "*", "@", "#", "$", "%", "&", "+", "="],
    ]

    def __init__(self, session: AsyncSession):
        self.session = session
        self.cipher = Fernet(key=settings.SECRET_KEY)

    async def get_all(self, user_id: int) -> list[str]:
        statement = select(Service.name).where(Service.user_id == user_id)
        results = await self.session.exec(statement=statement)
        return [name for name in results]

    async def get(self, user_id: int, name: str) -> str | None:
        statement = (
            select(Service.password)
            .where(Service.user_id == user_id)
            .where(Service.name == name)
        )
        results = await self.session.exec(statement=statement)
        return results.first()

    def generate_password(
        self,
        password: str = None,
        chars: list[str] = CHARS,
        length: int = secrets.SystemRandom().randrange(16, 24),
    ):
        while True:
            password = "".join(secrets.choice(chars) for _ in range(length))
            if (
                any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 2
                and sum(c in string.punctuation for c in password) >= 1
            ):
                break
        return password

    def encrypt_password(self, password: str):
        return self.cipher.encrypt(password.encode()).decode()

    def decrypt_password(self, password: str):
        return self.cipher.decrypt(password.encode()).decode()
