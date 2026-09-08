"""SHADOW-INTEL FastAPI entry point.

Only wires up cross-cutting concerns (CORS, logging, health/readiness) for
this phase. Feature routers are added as their domains are implemented.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.health import router as health_router
from app.core.config import settings
from app.infrastructure.logging import CorrelationIdMiddleware, configure_logging

configure_logging(settings.LOG_LEVEL)

app = FastAPI(title=settings.PROJECT_NAME, version=settings.PROJECT_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(CorrelationIdMiddleware)

app.include_router(health_router)
