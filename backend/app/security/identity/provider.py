"""IdentityProvider contract.

Resolves the authenticated User for a request. Authentication mechanics
(JWT, session, etc.) are an implementation detail behind this contract —
none are implemented yet.
"""
from __future__ import annotations

from typing import Protocol

from app.core.domain.identity import User


class IdentityProvider(Protocol):
    def authenticate(self, token: str) -> User | None:
        """Resolve a bearer token to a User, or None if invalid/expired."""
        ...
