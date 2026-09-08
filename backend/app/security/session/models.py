"""Authenticated session.

The bearer token handed to the client is never stored — only its SHA-256 hash
is — so a copy of the database cannot be replayed as a live session.
`session_id` is a separate non-secret identifier, safe to audit and log.

The session records *which* agency context is active, not the role and clearance
that context carries: those are re-read from the user store on every request so
a revoked clearance takes effect immediately.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class AuthenticationMethod(str, Enum):
    LOCAL_PASSWORD = "LOCAL_PASSWORD"


@dataclass(frozen=True)
class Session:
    session_id: str
    user_id: str
    created_at: str
    expires_at: str
    status: SessionStatus
    authentication_method: AuthenticationMethod
    correlation_id: str
    active_agency_id: str | None = None
    active_role_id: str | None = None
    active_department: str | None = None
    active_unit: str | None = None


@dataclass(frozen=True)
class IssuedSession:
    """A newly created session plus the one-time bearer token for the client."""

    session: Session
    token: str
