"""État éphémère dans Redis : codes envoyés par email et challenges de connexion 2FA.

Rien n'est stocké en clair : codes et tokens sont conservés sous forme de HMAC.
"""

import redis

from app.config import get_settings
from app.security import keyed_hash, numeric_code, opaque_token, safe_equal


def _register_attempt(r: redis.Redis, key: str) -> bool:
    """Compte une tentative. False (et suppression) si la limite est dépassée ou si la clé a expiré."""
    attempts = r.hincrby(key, "a", 1)
    if r.ttl(key) < 0:  # clé expirée entre-temps : hincrby l'a recréée sans TTL
        r.delete(key)
        return False
    if attempts > get_settings().max_code_attempts:
        r.delete(key)
        return False
    return True


# --- Codes à usage unique envoyés par email (vérification d'adresse) ---


def _code_key(purpose: str, subject: str) -> str:
    return f"code:{purpose}:{subject}"


def issue_code(r: redis.Redis, purpose: str, subject: str) -> str:
    code = numeric_code()
    key = _code_key(purpose, subject)
    pipe = r.pipeline()
    pipe.delete(key)
    pipe.hset(key, mapping={"h": keyed_hash(purpose, f"{subject}:{code}"), "a": 0})
    pipe.expire(key, get_settings().email_code_ttl)
    pipe.execute()
    return code


def verify_code(r: redis.Redis, purpose: str, subject: str, code: str) -> bool:
    key = _code_key(purpose, subject)
    stored = r.hget(key, "h")
    if stored is None or not _register_attempt(r, key):
        return False
    if not safe_equal(keyed_hash(purpose, f"{subject}:{code}"), stored):
        return False
    # Seul le premier appel qui supprime la clé gagne : pas de double usage concurrent.
    return r.delete(key) == 1


# --- Challenges de connexion : entre le mot de passe validé et le second facteur ---


def _challenge_key(token: str) -> str:
    return f"mfa:{keyed_hash('mfa', token)}"


def create_challenge(r: redis.Redis, user_id: int) -> str:
    token = opaque_token()
    key = _challenge_key(token)
    pipe = r.pipeline()
    pipe.hset(key, mapping={"uid": user_id, "a": 0})
    pipe.expire(key, get_settings().mfa_challenge_ttl)
    pipe.execute()
    return token


def challenge_user_id(r: redis.Redis, token: str) -> int | None:
    uid = r.hget(_challenge_key(token), "uid")
    return int(uid) if uid is not None else None


def set_challenge_email_code(r: redis.Redis, token: str) -> str:
    code = numeric_code()
    key = _challenge_key(token)
    r.hset(key, "c", keyed_hash("login", f"{key}:{code}"))
    return code


def check_challenge_email_code(r: redis.Redis, token: str, code: str) -> bool:
    key = _challenge_key(token)
    stored = r.hget(key, "c")
    return stored is not None and safe_equal(keyed_hash("login", f"{key}:{code}"), stored)


def register_challenge_attempt(r: redis.Redis, token: str) -> bool:
    return _register_attempt(r, _challenge_key(token))


def consume_challenge(r: redis.Redis, token: str) -> bool:
    return r.delete(_challenge_key(token)) == 1
