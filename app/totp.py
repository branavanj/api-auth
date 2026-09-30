import time

import pyotp
import redis

from app.config import get_settings
from app.security import safe_equal

STEP = 30


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=get_settings().totp_issuer)


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """Pas de temps correspondant au code, avec ±1 pas de tolérance pour la dérive d'horloge."""
    if not (len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret)
    current = int((now if now is not None else time.time()) // STEP)
    for step in (current - 1, current, current + 1):
        if safe_equal(totp.at(step * STEP), code):
            return step
    return None


def verify(r: redis.Redis, user_id: int, secret: str, code: str) -> bool:
    step = matching_step(secret, code)
    if step is None:
        return False
    # Anti-rejeu : un code intercepté ne peut pas être réutilisé dans sa fenêtre de validité.
    return bool(r.set(f"totp:used:{user_id}:{step}", 1, nx=True, ex=STEP * 4))
