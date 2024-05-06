from database import init_db
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import services, users


def create_app():
    app = FastAPI()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(services.router)
    app.include_router(users.router)

    @app.on_event("startup")
    async def on_startup():
        await init_db()

    return app


app = create_app()
