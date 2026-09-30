# Miroir de db/init/02-schema.sql, qui fait foi en production (contraintes CHECK, trigger, droits).
from datetime import datetime

from sqlalchemy import BigInteger, CHAR, DateTime, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base

# bigint sous Postgres ; SQLite n'auto-incrémente que les INTEGER PRIMARY KEY.
Id = BigInteger().with_variant(Integer, "sqlite")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Id, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    email_verified: Mapped[bool] = mapped_column(default=False)
    # Secret TOTP chiffré (Fernet). Présent mais totp_enabled=False pendant l'enrôlement.
    totp_secret: Mapped[str | None] = mapped_column(String(255), default=None)
    totp_enabled: Mapped[bool] = mapped_column(default=False)
    # Incrémenté pour invalider d'un coup tous les tokens de l'utilisateur.
    token_version: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    backup_codes: Mapped[list["BackupCode"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class BackupCode(Base):
    __tablename__ = "backup_codes"
    __table_args__ = (UniqueConstraint("user_id", "code_hash", name="backup_codes_user_code_key"),)

    id: Mapped[int] = mapped_column(Id, primary_key=True)
    user_id: Mapped[int] = mapped_column(Id, ForeignKey("users.id", ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(CHAR(64))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped[User] = relationship(back_populates="backup_codes")
