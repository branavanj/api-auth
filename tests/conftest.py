import os
import re

os.environ.setdefault("SECRET_KEY", "test-secret-key-test-secret-key-0123456789")
os.environ.setdefault("TOTP_ENCRYPTION_KEY", "q5Z8Wy2mB4mJmI5z3nQn9oS1l0bJ8p0u7F3c6o2v1xw=")
os.environ.setdefault("DATABASE_URL", "sqlite://")

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.mailer import get_email_sender
from app.main import app
from app.redis_client import get_redis

PASSWORD = "correct-horse-battery-staple"


class Outbox:
    def __init__(self):
        self.messages: list[dict] = []

    def send(self, to: str, subject: str, body: str) -> None:
        self.messages.append({"to": to, "subject": subject, "body": body})

    def last_code(self, to: str) -> str:
        msg = next(m for m in reversed(self.messages) if m["to"] == to)
        return re.search(r"\b(\d{6})\b", msg["body"]).group(1)


@pytest.fixture
def redis_client():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.fixture
def outbox():
    return Outbox()


@pytest.fixture
def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(engine, expire_on_commit=False)()
    yield session
    session.close()


@pytest.fixture
def client(db_session, redis_client, outbox):
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_redis] = lambda: redis_client
    app.dependency_overrides[get_email_sender] = lambda: outbox
    # Pas de `with` : le lifespan (create_all sur Postgres) ne tourne pas.
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def verified_user(client, outbox):
    """Compte inscrit avec email vérifié. Renvoie ses identifiants."""
    user = {"username": "alice", "email": "alice@example.com", "password": PASSWORD}
    assert client.post("/auth/register", json=user).status_code == 201
    code = outbox.last_code(user["email"])
    r = client.post("/auth/verify-email", json={"email": user["email"], "code": code})
    assert r.status_code == 200, r.text
    return user


def start_login(client, user) -> dict:
    r = client.post("/auth/login", json={"username": user["username"], "password": user["password"]})
    assert r.status_code == 200, r.text
    return r.json()


def login_with_email(client, outbox, user) -> dict:
    challenge = start_login(client, user)
    code = outbox.last_code(user["email"])
    r = client.post("/auth/2fa/verify", json={"mfa_token": challenge["mfa_token"], "method": "email", "code": code})
    assert r.status_code == 200, r.text
    return r.json()


def auth_header(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}
