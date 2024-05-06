import secrets
import string

from config import Settings
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

    def __init__(self, session: AsyncSession, settings: Settings):
        self.session = session
        self.settings = settings
        self.cipher: Fernet = Fernet(key=settings.SECRET_KEY)

    async def get_all(self, user_id: int) -> list[str]:
        """
        Retrieves all service names associated with a specific user from the database.

        Parameters:
        -----------
        user_id : int
            The unique identifier of the user whose services are to be retrieved.

        Returns:
        --------
        list[str]
            A list of service names associated with the given user.

        Notes:
        ------
        - This method is asynchronous and requires an `await` keyword when being called.
        - It executes a SQL query to fetch service names from the `Service` table filtered by the provided `user_id`.

        Example usage:
        --------------
        Assuming `services_service` is an instance of the class containing this method:
        ```python
        service_names = await services_service.get_all(user_id=123)
        ```
        """
        statement = select(Service.name).where(Service.user_id == user_id)
        results = await self.session.exec(statement=statement)
        return [name for name in results]

    async def get(self, user_id: int, name: str) -> str | None:
        """
        Retrieves the password for a specific service associated with a given user.

        Parameters:
        -----------
        user_id : int
            The unique identifier of the user whose service password is to be retrieved.
        name : str
            The name of the service for which the password is needed.

        Returns:
        --------
        str | None
            The password associated with the specified service name and user, or `None` if no such service is found.

        Notes:
        ------
        - This method is asynchronous and requires the `await` keyword when called.
        - It executes a SQL query to fetch the service password filtered by both `user_id` and `name`.

        Example usage:
        --------------
        Assuming `services_service` is an instance of the class containing this method:
        ```python
        password = await services_service.get(user_id=123, name="example_service")
        ```
        """
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
