"""Domain contracts for agency scoping.

An AgencyContext is the active agency scope a caller claims: which agency,
department and unit they are operating in, under which role and clearance.

The context is a *claim*, never a grant. Switching context does not grant
anything — every AgencyContext must be re-evaluated by the AuthorizationEngine,
which also rejects a context claiming more clearance than the user holds.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.core.domain.identity import Clearance, Role


@dataclass(frozen=True)
class Agency:
    id: str
    name: str
    plugin_id: str


@dataclass(frozen=True)
class AgencyContext:
    agency: Agency
    user_id: str
    role: Role
    clearance: Clearance
    department: str | None = None
    unit: str | None = None
    policy_profile: str = "default"
