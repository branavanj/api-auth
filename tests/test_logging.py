import json
import logging

from app.logging_config import JsonFormatter
from tests.conftest import PASSWORD, login_with_email


def events(caplog) -> list[str]:
    return [getattr(r, "event") for r in caplog.records if r.name == "audit"]


def test_request_id_is_returned_and_propagated(client):
    r = client.get("/health/live", headers={"X-Request-ID": "abc123"})
    assert r.headers["x-request-id"] == "abc123"
    generated = client.get("/health/live").headers["x-request-id"]
    assert len(generated) == 32


def test_access_log(client, caplog):
    caplog.set_level(logging.INFO)
    client.get("/health/live")
    access = [r for r in caplog.records if r.name == "access"]
    assert access and access[-1].status == 200 and access[-1].path == "/health/live"
    assert access[-1].duration_ms >= 0


def test_security_events_are_audited(client, outbox, verified_user, caplog):
    caplog.set_level(logging.INFO)
    client.post("/auth/login", json={"username": "alice", "password": "x" * 12})
    client.post("/auth/login", json={"username": "nobody", "password": "x" * 12})
    login_with_email(client, outbox, verified_user)
    assert events(caplog) == ["login.failed", "login.failed", "login.password_ok", "login.succeeded"]
    reasons = [r.reason for r in caplog.records if getattr(r, "event", None) == "login.failed"]
    assert reasons == ["bad_password", "unknown_user"]


def test_secrets_never_logged(client, outbox, verified_user, caplog):
    caplog.set_level(logging.DEBUG)
    tokens = login_with_email(client, outbox, verified_user)
    code = outbox.last_code(verified_user["email"])
    formatter = JsonFormatter()
    dump = "\n".join(formatter.format(r) for r in caplog.records)
    for secret in (PASSWORD, code, tokens["access_token"], tokens["refresh_token"]):
        assert secret not in dump


def test_json_format(caplog):
    record = logging.getLogger("audit").makeRecord(
        "audit", logging.INFO, __file__, 1, "login.succeeded", None, None, extra={"event": "login.succeeded", "user_id": 7}
    )
    line = json.loads(JsonFormatter().format(record))
    assert line["level"] == "INFO" and line["event"] == "login.succeeded" and line["user_id"] == 7
    assert "request_id" in line and line["ts"].endswith("Z")


def test_unexpected_error_is_logged_with_request_id_and_hidden(client, caplog):
    from app.main import app

    @app.get("/_boom")
    def boom():
        raise RuntimeError("détail interne secret")

    try:
        caplog.set_level(logging.INFO)
        c = type(client)(app, raise_server_exceptions=False)
        r = c.get("/_boom", headers={"X-Request-ID": "req-42"})
        assert r.status_code == 500
        assert r.json() == {"detail": "Erreur interne."}
        assert "secret" not in r.text
        errors = [rec for rec in caplog.records if rec.levelno == logging.ERROR]
        assert errors and errors[0].exc_info
        line = json.loads(JsonFormatter().format(errors[0]))
        assert line["request_id"] == "req-42"
    finally:
        app.router.routes = [rt for rt in app.router.routes if getattr(rt, "path", None) != "/_boom"]
