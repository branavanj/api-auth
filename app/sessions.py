"""Tokens de session : access token JWT court + refresh token opaque, rotatif, stocké dans Redis."""

import json
import logging

import redis
from fastapi import HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.logging_config import audit_event
from app.models import User
from app.security import create_access_token, keyed_hash, opaque_token


def _key(refresh_token: str) -> str:
    return keyed_hash("refresh", refresh_token)


def issue_tokens(r: redis.Redis, user: User) -> dict:
    settings = get_settings()
    refresh_token = opaque_token()
    r.set(
        f"refresh:{_key(refresh_token)}",
        json.dumps({"uid": user.id, "ver": user.token_version}),
        ex=settings.refresh_token_ttl,
    )
    return {
        "access_token": create_access_token(user.id, user.token_version),
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.access_token_ttl,
    }


def rotate(r: redis.Redis, db: Session, refresh_token: str) -> dict:
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token invalide.")
    h = _key(refresh_token)
    raw = r.getdel(f"refresh:{h}")

    if raw is None:
        # Un token déjà utilisé qui revient = probablement volé : on coupe toutes les sessions.
        reused_uid = r.get(f"refresh:used:{h}")
        if reused_uid is not None:
            user = db.get(User, int(reused_uid))
            if user is not None:
                user.token_version += 1
                db.commit()
                audit_event("session.refresh_reuse_detected", level=logging.WARNING, user_id=user.id)
        raise invalid

    data = json.loads(raw)
    r.set(f"refresh:used:{h}", data["uid"], ex=get_settings().refresh_token_ttl)

    user = db.get(User, data["uid"])
    if user is None or user.token_version != data["ver"]:
        raise invalid
    return issue_tokens(r, user)


def revoke(r: redis.Redis, refresh_token: str) -> None:
    r.delete(f"refresh:{_key(refresh_token)}")


# --- Cookie pour les navigateurs : le JavaScript ne peut pas lire un cookie httpOnly (protection XSS). ---


def set_refresh_cookie(response: Response, refresh_token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.refresh_cookie_name,
        refresh_token,
        max_age=settings.refresh_token_ttl,
        path=settings.refresh_cookie_path,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )


def clear_refresh_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        settings.refresh_cookie_name,
        path=settings.refresh_cookie_path,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )


def deliver(response: Response, tokens: dict, use_cookie: bool) -> dict:
    """Navigateur : refresh token en cookie seulement. Client API : dans le JSON seulement."""
    if not use_cookie:
        return tokens
    set_refresh_cookie(response, tokens["refresh_token"])
    return {**tokens, "refresh_token": None}
