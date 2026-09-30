import redis

from app.main import app
from app.redis_client import get_redis


def test_live(client):
    r = client.get("/health/live")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_ready_when_dependencies_up(client):
    r = client.get("/health/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["checks"]["database"]["status"] == "up"
    assert body["checks"]["redis"]["status"] == "up"


def test_ready_reports_redis_down(client):
    class DownRedis:
        def ping(self):
            raise redis.ConnectionError("boom")

    app.dependency_overrides[get_redis] = lambda: DownRedis()
    r = client.get("/health/ready")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "degraded"
    assert body["checks"]["redis"] == {"status": "down", "error": "ConnectionError"}
    assert body["checks"]["database"]["status"] == "up"


def test_redis_outage_returns_503_not_500(client):
    class DownRedis:
        def pipeline(self):
            raise redis.ConnectionError("boom")

    app.dependency_overrides[get_redis] = lambda: DownRedis()
    r = client.post("/auth/login", json={"username": "alice", "password": "x" * 12})
    assert r.status_code == 503
    assert r.json() == {"detail": "Service temporairement indisponible."}
