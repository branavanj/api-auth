from typing import Annotated

import redis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.mailer import EmailSender, get_email_sender
from app.models import User
from app.redis_client import get_redis
from app.security import decode_access_token

DB = Annotated[Session, Depends(get_db)]
Redis = Annotated[redis.Redis, Depends(get_redis)]
Mailer = Annotated[EmailSender, Depends(get_email_sender)]

_bearer = HTTPBearer(auto_error=False)


def client_ip(request: Request) -> str:
    # Derrière un reverse proxy, lancer uvicorn avec --proxy-headers --forwarded-allow-ips.
    return request.client.host if request.client else "unknown"


def get_current_user(
    db: DB, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]
) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Non authentifié.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None:
        raise unauthorized
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise unauthorized
    user = db.get(User, int(payload["sub"]))
    if user is None or user.token_version != payload.get("ver"):
        raise unauthorized
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
