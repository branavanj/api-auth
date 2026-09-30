from fastapi import APIRouter, HTTPException, status

from app.deps import DB, CurrentUser, Redis
from app.logging_config import audit_event
from app.rate_limit import enforce
from app.schemas import MessageOut, PasswordChangeIn, UserOut
from app.security import hash_password, verify_password

router = APIRouter(prefix="/me", tags=["compte"])


@router.get("", response_model=UserOut)
def me(user: CurrentUser):
    return user


@router.post("/password", response_model=MessageOut)
def change_password(body: PasswordChangeIn, user: CurrentUser, db: DB, r: Redis):
    enforce(r, f"password-change:{user.id}", limit=5, window=900)
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Mot de passe actuel incorrect.")

    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # déconnecte toutes les sessions existantes
    db.commit()
    audit_event("user.password_changed", user_id=user.id)
    return {"message": "Mot de passe modifié. Reconnectez-vous."}
