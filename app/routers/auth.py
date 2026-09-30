import logging

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app import backup_codes, sessions, stores, totp
from app.config import get_settings
from app.deps import DB, CurrentUser, Mailer, Redis, client_ip
from app.logging_config import audit_event
from app.mailer import EmailSender, deliver
from app.models import User
from app.rate_limit import enforce
from app.schemas import (
    EmailIn,
    LoginIn,
    LoginOut,
    MessageOut,
    MfaTokenIn,
    MfaVerifyIn,
    RefreshIn,
    RegisterIn,
    TokenPairOut,
    VerifyEmailIn,
)
from app.security import (
    burn_password_check,
    decrypt,
    hash_password,
    password_needs_rehash,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

INVALID_CODE = "Code invalide ou expiré."
INVALID_CREDENTIALS = "Identifiants invalides."


def _send_verification_code(r, bg: BackgroundTasks, mailer: EmailSender, user: User) -> None:
    code = stores.issue_code(r, "verify_email", str(user.id))
    minutes = get_settings().email_code_ttl // 60
    bg.add_task(
        deliver,
        mailer,
        user.email,
        "Vérifiez votre adresse email",
        f"Votre code de vérification : {code}\n\nIl expire dans {minutes} minutes.",
    )


def _methods_for(user: User) -> list[str]:
    # Avec une app TOTP activée, l'email n'est plus accepté : sinon l'email redeviendrait le maillon faible.
    return ["totp", "backup_code"] if user.totp_enabled else ["email"]


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=MessageOut)
def register(body: RegisterIn, request: Request, bg: BackgroundTasks, db: DB, r: Redis, mailer: Mailer):
    ip = client_ip(request)
    enforce(r, f"register:{ip}", limit=5, window=3600)

    user = User(username=body.username, email=body.email, password_hash=hash_password(body.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        audit_event("user.register_conflict", ip=ip)
        raise HTTPException(status.HTTP_409_CONFLICT, "Nom d'utilisateur ou email déjà utilisé.")

    audit_event("user.registered", user_id=user.id, ip=ip)
    _send_verification_code(r, bg, mailer, user)
    return {"message": "Compte créé. Un code de vérification a été envoyé par email."}


@router.post("/verify-email", response_model=MessageOut)
def verify_email(body: VerifyEmailIn, request: Request, db: DB, r: Redis):
    enforce(r, f"verify-email:{client_ip(request)}", limit=20, window=900)

    user = db.scalar(select(User).where(User.email == body.email))
    if user is None or user.email_verified or not stores.verify_code(r, "verify_email", str(user.id), body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_CODE)

    user.email_verified = True
    db.commit()
    audit_event("user.email_verified", user_id=user.id)
    return {"message": "Adresse email vérifiée."}


@router.post("/verify-email/resend", status_code=status.HTTP_202_ACCEPTED, response_model=MessageOut)
def resend_verification(body: EmailIn, request: Request, bg: BackgroundTasks, db: DB, r: Redis, mailer: Mailer):
    enforce(r, f"verify-email-send:ip:{client_ip(request)}", limit=10, window=3600)
    enforce(r, f"verify-email-send:{body.email}", limit=3, window=900)

    user = db.scalar(select(User).where(User.email == body.email))
    if user is not None and not user.email_verified:
        _send_verification_code(r, bg, mailer, user)
    # Réponse identique dans tous les cas : impossible de savoir si l'adresse existe.
    return {"message": "Si ce compte existe et n'est pas vérifié, un nouveau code a été envoyé."}


@router.post("/login", response_model=LoginOut)
def login(body: LoginIn, request: Request, bg: BackgroundTasks, db: DB, r: Redis, mailer: Mailer):
    ip = client_ip(request)
    enforce(r, f"login:ip:{ip}", limit=30, window=900)
    enforce(r, f"login:user:{body.username}", limit=10, window=900)

    user = db.scalar(select(User).where(User.username == body.username))
    if user is None:
        burn_password_check()
        audit_event("login.failed", level=logging.WARNING, reason="unknown_user", username=body.username, ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)
    if not verify_password(user.password_hash, body.password):
        audit_event("login.failed", level=logging.WARNING, reason="bad_password", user_id=user.id, ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, INVALID_CREDENTIALS)

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
        db.commit()

    if not user.email_verified:
        audit_event("login.blocked", reason="email_unverified", user_id=user.id, ip=ip)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Adresse email non vérifiée.")

    methods = _methods_for(user)
    token = stores.create_challenge(r, user.id)
    if "email" in methods:
        _send_login_code(r, bg, mailer, user, token)
    audit_event("login.password_ok", user_id=user.id, ip=ip, methods=methods)

    return LoginOut(mfa_token=token, methods=methods, expires_in=get_settings().mfa_challenge_ttl)


def _send_login_code(r, bg: BackgroundTasks, mailer: EmailSender, user: User, mfa_token: str) -> None:
    code = stores.set_challenge_email_code(r, mfa_token)
    bg.add_task(
        deliver,
        mailer,
        user.email,
        "Votre code de connexion",
        f"Votre code de connexion : {code}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, changez votre mot de passe.",
    )


@router.post("/2fa/resend", status_code=status.HTTP_202_ACCEPTED, response_model=MessageOut)
def resend_login_code(body: MfaTokenIn, bg: BackgroundTasks, db: DB, r: Redis, mailer: Mailer):
    user_id = stores.challenge_user_id(r, body.mfa_token)
    if user_id is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session de connexion expirée.")
    enforce(r, f"login-code-send:{user_id}", limit=3, window=600)

    user = db.get(User, user_id)
    if user is None or "email" not in _methods_for(user):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Ce compte n'utilise pas la vérification par email.")
    _send_login_code(r, bg, mailer, user, body.mfa_token)
    return {"message": "Un nouveau code a été envoyé."}


@router.post("/2fa/verify", response_model=TokenPairOut)
def verify_second_factor(body: MfaVerifyIn, request: Request, response: Response, db: DB, r: Redis):
    ip = client_ip(request)
    user_id = stores.challenge_user_id(r, body.mfa_token)
    user = db.get(User, user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session de connexion expirée.")
    if not stores.register_challenge_attempt(r, body.mfa_token):
        audit_event("mfa.locked", level=logging.WARNING, user_id=user.id, ip=ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Trop de tentatives, reconnectez-vous.")

    ok = False
    if body.method in _methods_for(user):
        if body.method == "email":
            ok = stores.check_challenge_email_code(r, body.mfa_token, body.code)
        elif body.method == "totp":
            ok = totp.verify(r, user.id, decrypt(user.totp_secret), body.code)
        elif body.method == "backup_code":
            ok = backup_codes.consume(db, user, body.code)
    if not ok:
        db.rollback()
        audit_event("mfa.failed", level=logging.WARNING, user_id=user.id, method=body.method, ip=ip)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_CODE)

    # Le challenge ne sert qu'une fois, même si deux requêtes arrivent en même temps.
    if not stores.consume_challenge(r, body.mfa_token):
        db.rollback()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session de connexion expirée.")
    db.commit()
    audit_event("login.succeeded", user_id=user.id, method=body.method, ip=ip)
    return sessions.deliver(response, sessions.issue_tokens(r, user), body.use_cookie)


def _refresh_token(request: Request, body: RefreshIn | None) -> tuple[str | None, bool]:
    """(token, vient_du_cookie). Le corps (clients API) a priorité sur le cookie (navigateurs)."""
    if body and body.refresh_token:
        return body.refresh_token, False
    return request.cookies.get(get_settings().refresh_cookie_name), True


@router.post("/refresh", response_model=TokenPairOut)
def refresh(request: Request, response: Response, db: DB, r: Redis, body: RefreshIn | None = None):
    token, from_cookie = _refresh_token(request, body)
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token invalide.")
    # La réponse suit le même canal que la requête.
    return sessions.deliver(response, sessions.rotate(r, db, token), use_cookie=from_cookie)


@router.post("/logout", response_model=MessageOut)
def logout(request: Request, response: Response, r: Redis, body: RefreshIn | None = None):
    token, _ = _refresh_token(request, body)
    if token is not None:
        sessions.revoke(r, token)
    sessions.clear_refresh_cookie(response)
    return {"message": "Déconnecté."}


@router.post("/logout-all", response_model=MessageOut)
def logout_all(user: CurrentUser, response: Response, db: DB):
    user.token_version += 1
    db.commit()
    sessions.clear_refresh_cookie(response)
    audit_event("session.logout_all", user_id=user.id)
    return {"message": "Toutes les sessions ont été fermées."}
