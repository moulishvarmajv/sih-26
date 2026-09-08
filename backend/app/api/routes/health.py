"""Liveness and readiness endpoints.

/health reports the process is up. /ready additionally reports the loaded
environment — it does not yet probe Neo4j or the event store since those
integrations don't exist in this phase.
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
