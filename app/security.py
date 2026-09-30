import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet

from app.config import get_settings

_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("dummy-password-used-to-equalize-timing")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def burn_password_check() -> None:
    """Même coût qu'une vraie vérification : un utilisateur inconnu ne se distingue pas au chrono."""
    verify_password(_DUMMY_HASH, "x")


def numeric_code(digits: int = 6) -> str:
    return f"{secrets.randbelow(10**digits):0{digits}d}"


def opaque_token() -> str:
    return secrets.token_urlsafe(32)


def _subkey(name: str) -> bytes:
    return hmac.new(get_settings().secret_key.encode(), name.encode(), hashlib.sha256).digest()


def keyed_hash(purpose: str, value: str) -> str:
    """HMAC-SHA256 : une fuite de Redis/Postgres ne permet pas de retrouver les codes."""
    return hmac.new(_subkey("hash"), f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()


def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def _fernet() -> Fernet:
    return Fernet(get_settings().totp_encryption_key.encode())


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()


def create_access_token(user_id: int, token_version: int) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "ver": token_version,
        "type": "access",
        "iss": settings.jwt_issuer,
        "iat": now,
        "exp": now + timedelta(seconds=settings.access_token_ttl),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, _subkey("jwt"), algorithm="HS256")


def decode_access_token(token: str) -> dict | None:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            _subkey("jwt"),
            algorithms=["HS256"],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.PyJWTError:
        return None
    if payload.get("type") != "access":
        return None
    return payload
