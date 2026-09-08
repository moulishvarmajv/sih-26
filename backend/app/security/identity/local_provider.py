"""Local username/password identity provider for the MVP.

Deterministic: the same credentials always resolve to the same principal, and
an unknown username costs the same work as a wrong password so timing does not
disclose which accounts exist.
"""
from __future__ import annotations

from app.core.domain.identity import User
from app.security.identity.models import (
    AccountStatus,
    AuthenticationOutcome,
    AuthenticationResult,
    Credentials,
)
from app.security.identity.passwords import PasswordHasher
from app.security.identity.user_store import SQLiteUserStore

_FAILED = AuthenticationResult(AuthenticationOutcome.INVALID_CREDENTIALS)


class LocalIdentityProvider:
    def __init__(self, store: SQLiteUserStore, hasher: PasswordHasher) -> None:
        self._store = store
        self._hasher = hasher

    def authenticate(self, credentials: Credentials) -> AuthenticationResult:
        account = self._store.get_account_by_username(credentials.username)
        if account is None:
            self._hasher.dummy_verify(credentials.password)
            return _FAILED

        if not self._hasher.verify(credentials.password, account.password_hash):
            return _FAILED

        if account.status is not AccountStatus.ACTIVE:
            return AuthenticationResult(AuthenticationOutcome.ACCOUNT_DISABLED)

        user = self._store.get_user(account.user_id)
        if user is None:  # pragma: no cover - account exists, so the user must resolve
            return _FAILED
        return AuthenticationResult(AuthenticationOutcome.SUCCESS, user=user)

    def get_user(self, user_id: str) -> User | None:
        return self._store.get_user(user_id)
