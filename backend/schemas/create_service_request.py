from database import BaseSchema


class CreateServiceRequest(BaseSchema):
    name: str
