"""AuthorizationEngine contract — the single source of truth for access decisions.

Every evidence access, agency switch, and case access must go through this
engine. The frontend must never compute or cache its own authorization
decision; it only renders what this engine allows.

Implementations must be pure: given the same request and facts they return the
same effect and reason, and they perform no storage or network access.
"""
from __future__ import annotations

from typing import Protocol

from app.core.domain.authorization import AuthorizationDecision
from app.security.authorization.models import AuthorizationFacts, AuthorizationRequest


class AuthorizationEngine(Protocol):
    def evaluate(
        self, request: AuthorizationRequest, facts: AuthorizationFacts
    ) -> AuthorizationDecision:
        """Combine role, clearance, agency, case, need-to-know and privacy policy.

        Must fail closed: any missing or ambiguous input results in DENY.
        """
        ...
