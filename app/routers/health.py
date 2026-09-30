import logging
import time

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.deps import DB, Redis

router = APIRouter(prefix="/health", tags=["santé"])
log = logging.getLogger(__name__)

_STARTED_AT = time.monotonic()


def _check(name: str, fn) -> dict:
    start = time.perf_counter()
    try:
        fn()
    except Exception as exc:
        log.warning("Dépendance indisponible : %s", name, extra={"dependency": name, "error": type(exc).__name__})
        return {"status": "down", "error": type(exc).__name__}
    return {"status": "up", "latency_ms": round((time.perf_counter() - start) * 1000, 1)}


@router.get("/live")
def live():
    """Le processus répond. Sert au redémarrage automatique (liveness probe)."""
    return {"status": "ok", "uptime_s": int(time.monotonic() - _STARTED_AT)}


@router.get("/ready")
def ready(response: Response, db: DB, r: Redis):
    """Postgres et Redis joignables. 503 sinon : le load balancer arrête d'envoyer du trafic."""
    checks = {
        "database": _check("database", lambda: db.execute(text("SELECT 1"))),
        "redis": _check("redis", r.ping),
    }
    healthy = all(c["status"] == "up" for c in checks.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if healthy else "degraded", "checks": checks}
