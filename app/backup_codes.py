import secrets
from datetime import datetime, timezone

from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from app.models import BackupCode, User
from app.security import keyed_hash

# Sans caractères ambigus (0/o, 1/l/i).
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
COUNT = 10


def _normalize(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def _hash(user_id: int, code: str) -> str:
    return keyed_hash("backup", f"{user_id}:{_normalize(code)}")


def _generate() -> str:
    raw = "".join(secrets.choice(_ALPHABET) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


def replace_codes(db: Session, user: User) -> list[str]:
    """Remplace tous les codes de secours de l'utilisateur. Les codes en clair ne sont renvoyés qu'une fois."""
    db.execute(delete(BackupCode).where(BackupCode.user_id == user.id))
    codes = [_generate() for _ in range(COUNT)]
    db.add_all(BackupCode(user_id=user.id, code_hash=_hash(user.id, c)) for c in codes)
    return codes


def consume(db: Session, user: User, code: str) -> bool:
    result = db.execute(
        update(BackupCode)
        .where(
            BackupCode.user_id == user.id,
            BackupCode.code_hash == _hash(user.id, code),
            BackupCode.used_at.is_(None),
        )
        .values(used_at=datetime.now(timezone.utc))
    )
    return result.rowcount == 1
