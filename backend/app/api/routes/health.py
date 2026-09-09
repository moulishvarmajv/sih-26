"""Liveness and readiness endpoints.

/health reports the process is up. /ready additionally reports which
environment was loaded.

Neither probes Neo4j, deliberately. The application is designed to serve every
non-graph route with the graph down, so a readiness check that failed on an
unreachable Neo4j would report the process unhealthy when it is working as
designed — and it would put a connection attempt, with its timeout, on an
endpoint an orchestrator polls. Graph availability is reported where it
matters: the graph routes answer GRAPH_UNAVAILABLE, and `docker compose ps`
carries the server's own healthcheck.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.core.config import settings

router = APIRouter(tags=["system"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def ready() -> dict[str, str]:
    return {"status": "ready", "environment": settings.ENVIRONMENT}
