from fastapi import APIRouter, HTTPException, status

from app import backup_codes, totp
from app.deps import DB, CurrentUser, Redis
from app.logging_config import audit_event
from app.models import User
from app.rate_limit import enforce
from app.schemas import BackupCodesOut, CodeIn, MessageOut, TotpDisableIn, TotpSetupOut
from app.security import decrypt, encrypt, verify_password

router = APIRouter(prefix="/2fa", tags=["double authentification"])

INVALID_CODE = "Code invalide."


def _limit(r, user: User) -> None:
    # Protège les codes TOTP à 6 chiffres contre la force brute par un détenteur de session.
    enforce(r, f"2fa-manage:{user.id}", limit=5, window=900)


def _require_totp_enabled(user: User) -> None:
    if not user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "L'application d'authentification n'est pas activée.")


@router.post("/totp/setup", response_model=TotpSetupOut)
def setup_totp(user: CurrentUser, db: DB):
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "L'application d'authentification est déjà activée.")
    secret = totp.new_secret()
    user.totp_secret = encrypt(secret)
    db.commit()
    return {"secret": secret, "otpauth_uri": totp.provisioning_uri(secret, user.email)}


@router.post("/totp/enable", response_model=BackupCodesOut)
def enable_totp(body: CodeIn, user: CurrentUser, db: DB, r: Redis):
    _limit(r, user)
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "L'application d'authentification est déjà activée.")
    if user.totp_secret is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Appelez d'abord /2fa/totp/setup.")
    # Activation seulement après un premier code valide : prouve que l'app est bien configurée.
    if not totp.verify(r, user.id, decrypt(user.totp_secret), body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_CODE)

    user.totp_enabled = True
    codes = backup_codes.replace_codes(db, user)
    db.commit()
    audit_event("mfa.totp_enabled", user_id=user.id)
    return {"backup_codes": codes}


@router.post("/totp/disable", response_model=MessageOut)
def disable_totp(body: TotpDisableIn, user: CurrentUser, db: DB, r: Redis):
    _limit(r, user)
    _require_totp_enabled(user)
    if not verify_password(user.password_hash, body.password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Mot de passe incorrect.")

    code_ok = totp.verify(r, user.id, decrypt(user.totp_secret), body.code) or backup_codes.consume(db, user, body.code)
    if not code_ok:
        db.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_CODE)

    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes.clear()
    db.commit()
    audit_event("mfa.totp_disabled", user_id=user.id)
    return {"message": "Application d'authentification désactivée. Le code par email est de nouveau utilisé."}


@router.post("/backup-codes/regenerate", response_model=BackupCodesOut)
def regenerate_backup_codes(body: CodeIn, user: CurrentUser, db: DB, r: Redis):
    _limit(r, user)
    _require_totp_enabled(user)
    if not totp.verify(r, user.id, decrypt(user.totp_secret), body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_CODE)

    codes = backup_codes.replace_codes(db, user)
    db.commit()
    audit_event("mfa.backup_codes_regenerated", user_id=user.id)
    return {"backup_codes": codes}
