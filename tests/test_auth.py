from tests.conftest import PASSWORD, auth_header, login_with_email, start_login


def test_full_email_flow(client, outbox, verified_user):
    tokens = login_with_email(client, outbox, verified_user)
    r = client.get("/me", headers=auth_header(tokens))
    assert r.status_code == 200
    assert r.json()["username"] == "alice"
    assert r.json()["totp_enabled"] is False


def test_register_normalizes_and_rejects_duplicates(client):
    user = {"username": "Bob", "email": "BOB@Example.com", "password": PASSWORD}
    assert client.post("/auth/register", json=user).status_code == 201
    dup = {"username": "bob", "email": "other@example.com", "password": PASSWORD}
    assert client.post("/auth/register", json=dup).status_code == 409


def test_register_rejects_short_password(client):
    r = client.post("/auth/register", json={"username": "bob", "email": "b@example.com", "password": "short"})
    assert r.status_code == 422


def test_login_requires_verified_email(client):
    user = {"username": "carol", "email": "carol@example.com", "password": PASSWORD}
    client.post("/auth/register", json=user)
    r = client.post("/auth/login", json={"username": "carol", "password": PASSWORD})
    assert r.status_code == 403


def test_wrong_password_and_unknown_user_look_identical(client, verified_user):
    wrong = client.post("/auth/login", json={"username": "alice", "password": "x" * 12})
    unknown = client.post("/auth/login", json={"username": "nobody", "password": "x" * 12})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_verify_email_code_is_single_use(client, outbox):
    user = {"username": "dave", "email": "dave@example.com", "password": PASSWORD}
    client.post("/auth/register", json=user)
    code = outbox.last_code(user["email"])
    assert client.post("/auth/verify-email", json={"email": user["email"], "code": code}).status_code == 200
    assert client.post("/auth/verify-email", json={"email": user["email"], "code": code}).status_code == 400


def test_resend_verification_does_not_leak_existence(client):
    r1 = client.post("/auth/verify-email/resend", json={"email": "ghost@example.com"})
    assert r1.status_code == 202


def test_email_code_cannot_be_reused(client, outbox, verified_user):
    challenge = start_login(client, verified_user)
    code = outbox.last_code(verified_user["email"])
    payload = {"mfa_token": challenge["mfa_token"], "method": "email", "code": code}
    assert client.post("/auth/2fa/verify", json=payload).status_code == 200
    assert client.post("/auth/2fa/verify", json=payload).status_code == 401


def test_challenge_dies_after_max_attempts(client, outbox, verified_user):
    challenge = start_login(client, verified_user)
    real_code = outbox.last_code(verified_user["email"])
    wrong = "000000" if real_code != "000000" else "111111"
    for _ in range(5):
        r = client.post("/auth/2fa/verify", json={"mfa_token": challenge["mfa_token"], "method": "email", "code": wrong})
        assert r.status_code == 400
    # Même le bon code est refusé : le challenge est détruit.
    r = client.post("/auth/2fa/verify", json={"mfa_token": challenge["mfa_token"], "method": "email", "code": real_code})
    assert r.status_code == 401


def test_challenge_expires(client, outbox, verified_user, redis_client):
    challenge = start_login(client, verified_user)
    keys = redis_client.keys("mfa:*")
    assert len(keys) == 1 and 0 < redis_client.ttl(keys[0]) <= 300
    redis_client.delete(keys[0])  # simule l'expiration
    code = outbox.last_code(verified_user["email"])
    r = client.post("/auth/2fa/verify", json={"mfa_token": challenge["mfa_token"], "method": "email", "code": code})
    assert r.status_code == 401


def test_nothing_sensitive_stored_in_clear(client, outbox, verified_user, redis_client):
    challenge = start_login(client, verified_user)
    code = outbox.last_code(verified_user["email"])
    dump = str({k: redis_client.hgetall(k) for k in redis_client.keys("mfa:*")})
    assert code not in dump and challenge["mfa_token"] not in dump


def test_resend_login_code(client, outbox, verified_user):
    challenge = start_login(client, verified_user)
    first = outbox.last_code(verified_user["email"])
    assert client.post("/auth/2fa/resend", json={"mfa_token": challenge["mfa_token"]}).status_code == 202
    second = outbox.last_code(verified_user["email"])
    if first != second:
        r = client.post("/auth/2fa/verify", json={"mfa_token": challenge["mfa_token"], "method": "email", "code": first})
        assert r.status_code == 400
    r = client.post("/auth/2fa/verify", json={"mfa_token": challenge["mfa_token"], "method": "email", "code": second})
    assert r.status_code == 200


def test_login_rate_limited(client, verified_user):
    for _ in range(10):
        client.post("/auth/login", json={"username": "alice", "password": "x" * 12})
    r = client.post("/auth/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_refresh_rotation(client, outbox, verified_user):
    tokens = login_with_email(client, outbox, verified_user)
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    new = r.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    assert client.get("/me", headers=auth_header(new)).status_code == 200


def test_refresh_reuse_revokes_all_sessions(client, outbox, verified_user):
    tokens = login_with_email(client, outbox, verified_user)
    new = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).json()
    # Rejeu de l'ancien refresh token : considéré comme un vol.
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.get("/me", headers=auth_header(new)).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": new["refresh_token"]}).status_code == 401


def test_logout_revokes_refresh_token(client, outbox, verified_user):
    tokens = login_with_email(client, outbox, verified_user)
    client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_logout_all(client, outbox, verified_user):
    a = login_with_email(client, outbox, verified_user)
    b = login_with_email(client, outbox, verified_user)
    assert client.post("/auth/logout-all", headers=auth_header(a)).status_code == 200
    assert client.get("/me", headers=auth_header(b)).status_code == 401


def test_password_change_invalidates_sessions(client, outbox, verified_user):
    tokens = login_with_email(client, outbox, verified_user)
    new_password = "another-long-password-42"
    r = client.post(
        "/me/password",
        json={"current_password": PASSWORD, "new_password": new_password},
        headers=auth_header(tokens),
    )
    assert r.status_code == 200
    assert client.get("/me", headers=auth_header(tokens)).status_code == 401
    login_with_email(client, outbox, {**verified_user, "password": new_password})


def test_rejects_garbage_tokens(client):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer nope"}).status_code == 401


def browser_login(client, outbox, user) -> dict:
    challenge = start_login(client, user)
    code = outbox.last_code(user["email"])
    r = client.post(
        "/auth/2fa/verify",
        json={"mfa_token": challenge["mfa_token"], "method": "email", "code": code, "use_cookie": True},
    )
    assert r.status_code == 200, r.text
    return r


def test_api_client_gets_no_cookie(client, outbox, verified_user):
    tokens = login_with_email(client, outbox, verified_user)
    assert tokens["refresh_token"]
    assert client.cookies.get("refresh_token") is None


def test_browser_flow_uses_httponly_cookie(client, outbox, verified_user):
    client.base_url = "https://testserver"  # cookie Secure : jamais renvoyé en HTTP clair
    r = browser_login(client, outbox, verified_user)
    # Le refresh token n'est jamais exposé au JavaScript.
    assert r.json()["refresh_token"] is None
    cookie = client.cookies.get("refresh_token")
    assert cookie
    # Refresh sans corps : le cookie suffit, il est remplacé, et toujours absent du JSON.
    r = client.post("/auth/refresh")
    assert r.status_code == 200 and r.json()["refresh_token"] is None
    assert client.cookies.get("refresh_token") not in (None, cookie)
    assert client.get("/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"}).status_code == 200
    # Logout sans corps : révoque et efface le cookie.
    assert client.post("/auth/logout").status_code == 200
    assert client.cookies.get("refresh_token") is None
    assert client.post("/auth/refresh").status_code == 401


def test_refresh_cookie_flags(client, outbox, verified_user):
    header = browser_login(client, outbox, verified_user).headers["set-cookie"].lower()
    for flag in ("httponly", "samesite=strict", "path=/auth", "secure"):
        assert flag in header
