"""Is a clearance grant currently valid?

One definition, used by both the authorization pipeline (to build facts) and the
login flow (to decide whether CLEARANCE_VERIFIED can be emitted), so the two can
never drift apart. This answers only "is the grant current" — never "may this
user do X", which remains the AuthorizationEngine's decision.
"""
from __future__ import annotations

from enum import Enum

from app.core.domain.identity import Clearance
from app.infrastructure.clock import parse_iso
from app.security.clearance.policy import ClearancePolicy


class ClearanceState(str, Enum):
    VALID = "VALID"
    MISSING = "MISSING"
    UNKNOWN_LEVEL = "UNKNOWN_LEVEL"
    EXPIRED = "EXPIRED"


def is_expired(clearance: Clearance | None, now: str) -> bool:
    if clearance is None or clearance.expires_at is None:
        return False
    try:
        return parse_iso(clearance.expires_at) <= parse_iso(now)
    except ValueError:
        return True  # an unparseable expiry is treated as expired


def verify_clearance(
    clearance: Clearance | None, policy: ClearancePolicy, now: str
) -> ClearanceState:
    if clearance is None:
        return ClearanceState.MISSING
    if not policy.knows(clearance.level_code):
        return ClearanceState.UNKNOWN_LEVEL
    if is_expired(clearance, now):
        return ClearanceState.EXPIRED
    return ClearanceState.VALID
