"""Domain contract for authorization outcomes.

An AuthorizationDecision is the only thing an AuthorizationEngine may produce;
nothing in the system may treat clearance, role, or agency membership alone as
sufficient for access.

A decision carries the facts it was made from so it can be audited and replayed.
It never carries evidence payload — denials in particular must not leak the data
they denied. `redacted_fields` holds field *names* only.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AuthorizationEffect(str, Enum):
    ALLOW = "ALLOW"
    PARTIAL = "PARTIAL"
    DENY = "DENY"


class ReasonCode(str, Enum):
    ACCESS_GRANTED = "ACCESS_GRANTED"
    PRIVACY_MASK_APPLIED = "PRIVACY_MASK_APPLIED"
    IDENTITY_CONTEXT_MISMATCH = "IDENTITY_CONTEXT_MISMATCH"
    CLEARANCE_MISSING = "CLEARANCE_MISSING"
    CLEARANCE_LEVEL_UNKNOWN = "CLEARANCE_LEVEL_UNKNOWN"
    CLEARANCE_EXPIRED = "CLEARANCE_EXPIRED"
    CONTEXT_CLEARANCE_ESCALATION = "CONTEXT_CLEARANCE_ESCALATION"
    AGENCY_ACCESS_DENIED = "AGENCY_ACCESS_DENIED"
    CASE_AGENCY_MISMATCH = "CASE_AGENCY_MISMATCH"
    CASE_ACCESS_DENIED = "CASE_ACCESS_DENIED"
    EVIDENCE_CASE_MISMATCH = "EVIDENCE_CASE_MISMATCH"
    NEED_TO_KNOW_DENIED = "NEED_TO_KNOW_DENIED"
    ROLE_ACTION_DENIED = "ROLE_ACTION_DENIED"
    CLEARANCE_INSUFFICIENT = "CLEARANCE_INSUFFICIENT"


class PrivacyAction(str, Enum):
    NONE = "NONE"
    MASK = "MASK"


@dataclass(frozen=True)
class AuthorizationDecision:
    effect: AuthorizationEffect
    reason: ReasonCode
    user_id: str
    agency_id: str
    action: str
    timestamp: str
    correlation_id: str
    case_id: str | None = None
    evidence_id: str | None = None
    user_clearance: str | None = None
    required_clearance: str | None = None
    agency_allowed: bool | None = None
    case_allowed: bool | None = None
    need_to_know: bool | None = None
    privacy_action: PrivacyAction = PrivacyAction.NONE
    redacted_fields: tuple[str, ...] = ()

    @property
    def grants_access(self) -> bool:
        """True for ALLOW and PARTIAL; PARTIAL still requires masking to be applied."""
        return self.effect in (AuthorizationEffect.ALLOW, AuthorizationEffect.PARTIAL)

    @property
    def is_denied(self) -> bool:
        return self.effect is AuthorizationEffect.DENY

    def to_audit_payload(self) -> dict[str, Any]:
        """Audit-safe projection: decision facts only, never resource content."""
        return {
            "decision": self.effect.value,
            "reason": self.reason.value,
            "user_id": self.user_id,
            "agency": self.agency_id,
            "action": self.action,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "user_clearance": self.user_clearance,
            "required_clearance": self.required_clearance,
            "agency_allowed": self.agency_allowed,
            "case_allowed": self.case_allowed,
            "need_to_know": self.need_to_know,
            "privacy_action": self.privacy_action.value,
            "redacted_fields": list(self.redacted_fields),
        }
