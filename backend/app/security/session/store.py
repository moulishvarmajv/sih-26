"""Session persistence behind a protocol.

SQLite for the MVP; a distributed session service replaces it without touching
the authentication service or the routes. Lookup is by token hash, so the store
never holds a usable credential.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Protocol

from app.security.session.models import (
    AuthenticationMethod,
    IssuedSession,
    Session,
    SessionStatus,
)

_TOKEN_BYTES = 32

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash            TEXT PRIMARY KEY,
    session_id            TEXT NOT NULL UNIQUE,
    user_id               TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    expires_at            TEXT NOT NULL,
    status                TEXT NOT NULL,
    authentication_method TEXT NOT NULL,
    correlation_id        TEXT NOT NULL,
    active_agency_id      TEXT,
    active_role_id        TEXT,
    active_department     TEXT,
    active_unit           TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
"""


class SessionStoreError(Exception):
    """Raised when a session cannot be recorded or read."""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionStore(Protocol):
    def create(
        self,
        user_id: str,
        created_at: str,
        expires_at: str,
        authentication_method: AuthenticationMethod,
        correlation_id: str,
    ) -> IssuedSession:
        """Issue a new session and return it with its one-time bearer token."""
        ...

    def get_by_token(self, token: str) -> Session | None:
        """Resolve a bearer token to a session, or None if no such session exists."""
        ...

    def mark_expired(self, session_id: str) -> None:
        """Record that a session has passed its expiry."""
        ...

    def set_active_context(
        self,
        session_id: str,
        agency_id: str,
        role_id: str,
        department: str | None = None,
        unit: str | None = None,
    ) -> None:
        """Record which agency context the session is operating in."""
        ...


class SQLiteSessionStore:
    def __init__(self, database_path: str | Path) -> None:
        self._lock = threading.Lock()
        path = str(database_path)
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock, self._connection:
            self._connection.executescript(_SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def create(
        self,
        user_id: str,
        created_at: str,
        expires_at: str,
        authentication_method: AuthenticationMethod,
        correlation_id: str,
    ) -> IssuedSession:
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        session = Session(
            session_id=secrets.token_hex(16),
            user_id=user_id,
            created_at=created_at,
            expires_at=expires_at,
            status=SessionStatus.ACTIVE,
            authentication_method=authentication_method,
            correlation_id=correlation_id,
        )
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO sessions (
                        token_hash, session_id, user_id, created_at, expires_at,
                        status, authentication_method, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        hash_token(token),
                        session.session_id,
                        session.user_id,
                        session.created_at,
                        session.expires_at,
                        session.status.value,
                        session.authentication_method.value,
                        session.correlation_id,
                    ),
                )
        except sqlite3.Error as exc:
            raise SessionStoreError(f"failed to create session: {exc}") from exc
        return IssuedSession(session=session, token=token)

    def get_by_token(self, token: str) -> Session | None:
        row = self._fetch_one(
            "SELECT * FROM sessions WHERE token_hash = ?", (hash_token(token),)
        )
        return None if row is None else _to_session(row)

    def mark_expired(self, session_id: str) -> None:
        self._execute(
            "UPDATE sessions SET status = ? WHERE session_id = ?",
            (SessionStatus.EXPIRED.value, session_id),
        )

    def set_active_context(
        self,
        session_id: str,
        agency_id: str,
        role_id: str,
        department: str | None = None,
        unit: str | None = None,
    ) -> None:
        self._execute(
            "UPDATE sessions SET active_agency_id = ?, active_role_id = ?, "
            "active_department = ?, active_unit = ? WHERE session_id = ?",
            (agency_id, role_id, department, unit, session_id),
        )

    def _execute(self, sql: str, parameters: tuple) -> None:
        try:
            with self._lock, self._connection:
                self._connection.execute(sql, parameters)
        except sqlite3.Error as exc:
            raise SessionStoreError(f"failed to update session: {exc}") from exc

    def _fetch_one(self, sql: str, parameters: tuple) -> sqlite3.Row | None:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchone()
        except sqlite3.Error as exc:
            raise SessionStoreError(f"failed to read session: {exc}") from exc


def _to_session(row: sqlite3.Row) -> Session:
    return Session(
        session_id=row["session_id"],
        user_id=row["user_id"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        status=SessionStatus(row["status"]),
        authentication_method=AuthenticationMethod(row["authentication_method"]),
        correlation_id=row["correlation_id"],
        active_agency_id=row["active_agency_id"],
        active_role_id=row["active_role_id"],
        active_department=row["active_department"],
        active_unit=row["active_unit"],
    )
