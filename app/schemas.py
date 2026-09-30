from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field

Password = Field(min_length=12, max_length=128)


def _lower(v: str) -> str:
    return v.strip().lower()


Email = Annotated[EmailStr, AfterValidator(_lower)]


class MessageOut(BaseModel):
    message: str


class RegisterIn(BaseModel):
    username: Annotated[str, Field(pattern=r"^[a-zA-Z0-9_.-]{3,32}$"), AfterValidator(_lower)]
    email: Email
    password: str = Password


class EmailIn(BaseModel):
    email: Email


class VerifyEmailIn(EmailIn):
    code: str = Field(pattern=r"^\d{6}$")


class LoginIn(BaseModel):
    username: Annotated[str, Field(max_length=32), AfterValidator(_lower)]
    password: str = Field(max_length=128)


class LoginOut(BaseModel):
    mfa_required: Literal[True] = True
    mfa_token: str
    methods: list[Literal["email", "totp", "backup_code"]]
    expires_in: int


class MfaVerifyIn(BaseModel):
    mfa_token: str = Field(max_length=128)
    method: Literal["email", "totp", "backup_code"]
    code: str = Field(max_length=32)
    # Navigateur : refresh token en cookie httpOnly uniquement, jamais dans le JSON.
    use_cookie: bool = False


class MfaTokenIn(BaseModel):
    mfa_token: str = Field(max_length=128)


class TokenPairOut(BaseModel):
    access_token: str
    # Absent quand le refresh token est posé en cookie (le JavaScript ne doit pas pouvoir le lire).
    refresh_token: str | None = None
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class RefreshIn(BaseModel):
    # Facultatif : un navigateur l'envoie via le cookie httpOnly.
    refresh_token: str | None = Field(default=None, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    email_verified: bool
    totp_enabled: bool
    created_at: datetime | None


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=128)
    new_password: str = Password


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


class CodeIn(BaseModel):
    code: str = Field(max_length=32)


class TotpDisableIn(BaseModel):
    password: str = Field(max_length=128)
    code: str = Field(max_length=32, description="Code TOTP ou code de secours")


class BackupCodesOut(BaseModel):
    backup_codes: list[str]
