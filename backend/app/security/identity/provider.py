"""IdentityProvider contract.

Answers "who is this?" and nothing else. It resolves credentials to an
authenticated principal; whether that principal may *do* anything is the
AuthorizationEngine's decision, never this component's.

Implementations are adapters: LocalIdentityProvider today, an enterprise or
government provider later, without changes above this boundary.
"""
from __future__ import annotations

from typing import Protocol

from app.core.domain.identity import User
from app.security.identity.models import AuthenticationResult, Credentials


class IdentityProvider(Protocol):
    def authenticate(self, credentials: Credentials) -> AuthenticationResult:
        """Verify credentials and resolve the principal.

        Returns a result whose outcome distinguishes invalid credentials from a
        disabled account for *audit* purposes. Callers must collapse every
        non-success outcome into one generic API error so responses never reveal
        whether a username exists.
        """
        ...

    def get_user(self, user_id: str) -> User | None:
        """Resolve a known principal by id, without credentials."""
        ...
