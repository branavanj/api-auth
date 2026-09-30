from functools import lru_cache

import redis

from app.config import get_settings


@lru_cache
def _client() -> redis.Redis:
    return redis.Redis.from_url(
        get_settings().redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2
    )


def get_redis() -> redis.Redis:
    return _client()
