from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Auth API"
    log_level: str = "INFO"

    database_url: str = "postgresql+psycopg://auth:auth@localhost:5432/auth"
    redis_url: str = "redis://localhost:6379/0"
    db_auto_create: bool = False

    # Clé maîtresse : les clés JWT et HMAC en sont dérivées.
    secret_key: str = Field(min_length=32)
    # Clé Fernet (chiffrement des secrets TOTP en base).
    totp_encryption_key: str

    jwt_issuer: str = "auth-api"
    access_token_ttl: int = 15 * 60
    refresh_token_ttl: int = 7 * 24 * 3600
    # Refresh token aussi posé en cookie httpOnly, pour les navigateurs.
    refresh_cookie_name: str = "refresh_token"
    refresh_cookie_path: str = "/auth"  # "/api/auth" derrière le proxy du frontend
    cookie_secure: bool = True  # false uniquement en local sans HTTPS
    mfa_challenge_ttl: int = 5 * 60
    email_code_ttl: int = 10 * 60
    max_code_attempts: int = 5

    totp_issuer: str = "Auth API"

    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_security: str = "none"  # none | starttls | ssl
    email_from: str = "no-reply@example.com"


@lru_cache
def get_settings() -> Settings:
    return Settings()
