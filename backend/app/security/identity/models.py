"""Identity records and authentication results.

`UserAccount` is the persistence record and is the *only* type that carries a
password hash — it must never reach the API layer. Everything above the
identity boundary works with the domain `User`, which has no password material
at all, so leaking a hash requires deliberately crossing a type boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from app.core.domain.identity import User


class AccountStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class AuthenticationOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str  # never logged, never persisted, never returned


@dataclass(frozen=True)
class UserAccount:
    user_id: str
    username: str
    password_hash: str
    display_name: str
    status: AccountStatus
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AuthenticationResult:
    outcome: AuthenticationOutcome
    user: User | None = None

    @property
    def succeeded(self) -> bool:
        return self.outcome is AuthenticationOutcome.SUCCESS
