import logging

import redis
from fastapi import HTTPException, status

from app.logging_config import audit_event


def enforce(r: redis.Redis, key: str, limit: int, window: int) -> None:
    """Fenêtre fixe : au plus `limit` appels par `window` secondes pour `key`."""
    k = f"rl:{key}"
    pipe = r.pipeline()
    pipe.set(k, 0, ex=window, nx=True)
    pipe.incr(k)
    pipe.ttl(k)
    _, count, ttl = pipe.execute()
    if count > limit:
        if count == limit + 1:  # une seule ligne par fenêtre, pas une par requête bloquée
            audit_event("rate_limit.exceeded", level=logging.WARNING, key=key, limit=limit, window_s=window)
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Trop de requêtes, réessayez plus tard.",
            headers={"Retry-After": str(max(ttl, 1))},
        )
