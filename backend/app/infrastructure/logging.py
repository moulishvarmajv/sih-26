"""Structured logging + correlation ID foundation.

Minimal structured logging via stdlib logging, and a middleware that
attaches a per-request correlation ID for future distributed tracing.
No external logging service is used.
"""
from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")


def current_correlation_id() -> str:
    """Correlation id for the in-flight request, or '-' outside a request."""
    return _correlation_id.get()


class _CorrelationIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = _correlation_id.get()
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.addFilter(_CorrelationIdFilter())
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s level=%(levelname)s correlation_id=%(correlation_id)s "
            "logger=%(name)s message=%(message)s"
        )
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        token = _correlation_id.set(correlation_id)
        try:
            response = await call_next(request)
        finally:
            _correlation_id.reset(token)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
