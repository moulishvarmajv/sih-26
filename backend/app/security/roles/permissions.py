"""Role permission checks.

A role grants actions explicitly, or holds the wildcard. This answers only
"does the role name this action" — it is one input to authorization, never a
decision on its own.
"""
from __future__ import annotations

from app.core.domain.identity import Role

WILDCARD = "*"


def role_permits(role: Role, action: str) -> bool:
    return WILDCARD in role.permissions or action in role.permissions
