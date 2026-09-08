"""Domain contracts for identity and access concepts.

These are typed data contracts only. Clearance is intentionally kept separate
from authorization (see core/domain/authorization.py) — holding a clearance
level never implies an AuthorizationDecision on its own.

Clearance levels are referenced by code ("L1", "L2", ...) and resolved against
the active clearance policy; their ordering and meaning live in policy data,
never in this module.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Role:
    id: str
    name: str
    permissions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Clearance:
    level_code: str
    granted_by: str
    granted_at: str  # ISO-8601 timestamp
    expires_at: str | None = None


@dataclass(frozen=True)
class User:
    id: str
    username: str
    roles: tuple[Role, ...] = ()
    clearance: Clearance | None = None
