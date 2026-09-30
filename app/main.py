import logging
from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError

from app.config import get_settings
from app.db import Base, get_engine
from app.logging_config import RequestLoggingMiddleware, setup_logging
from app.routers import auth, health, me, twofa

settings = get_settings()
setup_logging(settings.log_level)
log = logging.getLogger("app")


@asynccontextmanager
async def lifespan(_: FastAPI):
    # En production le schéma vient de db/init/*.sql ; create_all ne sert que sans Postgres (SQLite).
    if settings.db_auto_create:
        Base.metadata.create_all(get_engine())
    log.info("Démarrage de l'API")
    yield
    log.info("Arrêt de l'API")


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(RequestLoggingMiddleware)
app.include_router(auth.router)
app.include_router(twofa.router)
app.include_router(me.router)
app.include_router(health.router)


@app.exception_handler(redis.RedisError)
@app.exception_handler(OperationalError)
async def dependency_unavailable(request: Request, exc: Exception):
    log.error(
        "Dépendance indisponible sur %s %s",
        request.method,
        request.url.path,
        extra={"error": type(exc).__name__},
    )
    return JSONResponse(
        {"detail": "Service temporairement indisponible."},
        status_code=503,
        headers={"Retry-After": "5"},
    )
