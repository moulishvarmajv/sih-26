"""Inputs to an authorization evaluation.

The engine is a pure function of (request, facts, policy). Facts are resolved by
the service layer — which owns repositories and clocks — so the engine itself
never touches storage or time. `None` on a fact means "not applicable to this
request" (e.g. no case is involved) rather than "unknown"; unknown facts must be
resolved to False by the caller, because the engine fails closed.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationRequest:
    user_id: str
    agency_id: str
    action: str
    correlation_id: str
    timestamp: str  # supplied by the caller so the engine stays clock-free and pure
    case_id: str | None = None
    evidence_id: str | None = None


@dataclass(frozen=True)
class AuthorizationFacts:
    identity_matches_context: bool
    agency_allowed: bool
    role_permits_action: bool
    user_clearance: str | None
    clearance_expired: bool
    context_clearance_escalated: bool
    required_clearance: str | None = None  # None resolves to the policy default
    case_belongs_to_agency: bool | None = None
    case_allowed: bool | None = None
    evidence_belongs_to_case: bool | None = None
    need_to_know: bool | None = None
    sensitive_fields: tuple[str, ...] = ()
