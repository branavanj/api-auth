import time

import pyotp
import pytest

from tests.conftest import PASSWORD, auth_header, login_with_email, start_login


def code_at(secret: str, offset_steps: int) -> str:
    return pyotp.TOTP(secret).at(time.time() + 30 * offset_steps)


@pytest.fixture
def totp_user(client, outbox, verified_user):
    """Utilisateur avec TOTP activé. Le code du pas courant (0) a déjà servi à l'activation."""
    tokens = login_with_email(client, outbox, verified_user)
    setup = client.post("/2fa/totp/setup", headers=auth_header(tokens)).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    r = client.post("/2fa/totp/enable", json={"code": code_at(setup["secret"], 0)}, headers=auth_header(tokens))
    assert r.status_code == 200, r.text
    return {**verified_user, "secret": setup["secret"], "backup_codes": r.json()["backup_codes"], "tokens": tokens}


def verify(client, challenge, method, code):
    return client.post("/auth/2fa/verify", json={"mfa_token": challenge["mfa_token"], "method": method, "code": code})


def test_enable_requires_valid_code(client, outbox, verified_user):
    tokens = login_with_email(client, outbox, verified_user)
    client.post("/2fa/totp/setup", headers=auth_header(tokens))
    r = client.post("/2fa/totp/enable", json={"code": "abcdef"}, headers=auth_header(tokens))
    assert r.status_code == 400
    assert client.get("/me", headers=auth_header(tokens)).json()["totp_enabled"] is False


def test_secret_encrypted_at_rest(totp_user, db_session):
    from app.models import User

    user = db_session.query(User).one()
    assert user.totp_secret and totp_user["secret"] not in user.totp_secret


def test_login_with_totp(client, outbox, totp_user):
    sent_before = len(outbox.messages)
    challenge = start_login(client, totp_user)
    assert challenge["methods"] == ["totp", "backup_code"]
    assert len(outbox.messages) == sent_before  # pas d'email quand le TOTP est actif
    assert verify(client, challenge, "totp", code_at(totp_user["secret"], 1)).status_code == 200


def test_email_method_refused_when_totp_enabled(client, totp_user):
    challenge = start_login(client, totp_user)
    assert verify(client, challenge, "email", "123456").status_code == 400


def test_totp_code_cannot_be_replayed(client, totp_user):
    code = code_at(totp_user["secret"], 1)
    assert verify(client, start_login(client, totp_user), "totp", code).status_code == 200
    assert verify(client, start_login(client, totp_user), "totp", code).status_code == 400


def test_backup_code_is_single_use(client, totp_user):
    assert len(totp_user["backup_codes"]) == 10
    code = totp_user["backup_codes"][0]
    assert verify(client, start_login(client, totp_user), "backup_code", code.upper()).status_code == 200
    assert verify(client, start_login(client, totp_user), "backup_code", code).status_code == 400


def test_regenerate_backup_codes_invalidates_old_ones(client, totp_user):
    r = client.post(
        "/2fa/backup-codes/regenerate",
        json={"code": code_at(totp_user["secret"], 1)},
        headers=auth_header(totp_user["tokens"]),
    )
    assert r.status_code == 200
    old = totp_user["backup_codes"][0]
    assert verify(client, start_login(client, totp_user), "backup_code", old).status_code == 400
    new = r.json()["backup_codes"][0]
    assert verify(client, start_login(client, totp_user), "backup_code", new).status_code == 200


def test_disable_totp_falls_back_to_email(client, outbox, totp_user):
    headers = auth_header(totp_user["tokens"])
    bad = client.post("/2fa/totp/disable", json={"password": "wrong-password!", "code": totp_user["backup_codes"][0]}, headers=headers)
    assert bad.status_code == 400
    r = client.post("/2fa/totp/disable", json={"password": PASSWORD, "code": totp_user["backup_codes"][0]}, headers=headers)
    assert r.status_code == 200
    assert start_login(client, totp_user)["methods"] == ["email"]
    login_with_email(client, outbox, totp_user)


def test_manage_endpoints_rate_limited(client, totp_user):
    headers = auth_header(totp_user["tokens"])
    for _ in range(5):
        client.post("/2fa/backup-codes/regenerate", json={"code": "000000"}, headers=headers)
    r = client.post("/2fa/backup-codes/regenerate", json={"code": "000000"}, headers=headers)
    assert r.status_code == 429
