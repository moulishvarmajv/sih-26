"""Local SQLite user store.

Holds accounts, their role assignments and their clearance grant. It returns
either a `UserAccount` (carries the password hash — for the identity provider
only) or a domain `User` (no password material — for everyone else).

Clearance and roles are read live rather than copied into sessions, so revoking
a clearance takes effect on the next request instead of at session expiry.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from app.core.domain.identity import Clearance, Role, User
from app.infrastructure.clock import utc_now_iso
from app.security.identity.models import AccountStatus, UserAccount

_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_accounts (
    user_id                TEXT PRIMARY KEY,
    username               TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash          TEXT NOT NULL,
    display_name           TEXT NOT NULL,
    status                 TEXT NOT NULL,
    clearance_level        TEXT,
    clearance_granted_by   TEXT,
    clearance_granted_at   TEXT,
    clearance_expires_at   TEXT,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS roles (
    role_id     TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    permissions TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id)
);
"""


class UserStoreError(Exception):
    """Raised when the user store cannot be read or written."""


class SQLiteUserStore:
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

    def upsert_role(self, role: Role) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO roles (role_id, name, permissions) VALUES (?, ?, ?) "
                "ON CONFLICT(role_id) DO UPDATE SET name=excluded.name, "
                "permissions=excluded.permissions",
                (role.id, role.name, json.dumps(list(role.permissions))),
            )

    def create_account(
        self,
        user_id: str,
        username: str,
        password_hash: str,
        display_name: str,
        status: AccountStatus = AccountStatus.ACTIVE,
        clearance: Clearance | None = None,
        role_ids: tuple[str, ...] = (),
    ) -> UserAccount:
        now = utc_now_iso()
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO user_accounts (
                        user_id, username, password_hash, display_name, status,
                        clearance_level, clearance_granted_by, clearance_granted_at,
                        clearance_expires_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        username,
                        password_hash,
                        display_name,
                        status.value,
                        clearance.level_code if clearance else None,
                        clearance.granted_by if clearance else None,
                        clearance.granted_at if clearance else None,
                        clearance.expires_at if clearance else None,
                        now,
                        now,
                    ),
                )
                self._connection.executemany(
                    "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                    [(user_id, role_id) for role_id in role_ids],
                )
        except sqlite3.IntegrityError as exc:
            raise UserStoreError(f"cannot create account '{user_id}': {exc}") from exc

        account = self.get_account_by_username(username)
        if account is None:  # pragma: no cover - insert succeeded, read back must work
            raise UserStoreError(f"account '{user_id}' vanished after creation")
        return account

    def set_status(self, user_id: str, status: AccountStatus) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE user_accounts SET status = ?, updated_at = ? WHERE user_id = ?",
                (status.value, utc_now_iso(), user_id),
            )

    def get_account_by_username(self, username: str) -> UserAccount | None:
        row = self._fetch_one(
            "SELECT * FROM user_accounts WHERE username = ? COLLATE NOCASE", (username,)
        )
        return None if row is None else _to_account(row)

    def get_user(self, user_id: str) -> User | None:
        row = self._fetch_one("SELECT * FROM user_accounts WHERE user_id = ?", (user_id,))
        return None if row is None else self._to_user(row)

    def get_user_by_username(self, username: str) -> User | None:
        row = self._fetch_one(
            "SELECT * FROM user_accounts WHERE username = ? COLLATE NOCASE", (username,)
        )
        return None if row is None else self._to_user(row)

    def _roles_for(self, user_id: str) -> tuple[Role, ...]:
        rows = self._fetch_all(
            "SELECT r.role_id, r.name, r.permissions FROM roles r "
            "JOIN user_roles ur ON ur.role_id = r.role_id WHERE ur.user_id = ? "
            "ORDER BY r.role_id",
            (user_id,),
        )
        return tuple(
            Role(id=row["role_id"], name=row["name"], permissions=tuple(json.loads(row["permissions"])))
            for row in rows
        )

    def _to_user(self, row: sqlite3.Row) -> User:
        clearance = None
        if row["clearance_level"]:
            clearance = Clearance(
                level_code=row["clearance_level"],
                granted_by=row["clearance_granted_by"] or "UNKNOWN",
                granted_at=row["clearance_granted_at"] or "",
                expires_at=row["clearance_expires_at"],
            )
        return User(
            id=row["user_id"],
            username=row["username"],
            roles=self._roles_for(row["user_id"]),
            clearance=clearance,
            display_name=row["display_name"],
        )

    def _fetch_one(self, sql: str, parameters: tuple) -> sqlite3.Row | None:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchone()
        except sqlite3.Error as exc:
            raise UserStoreError(f"failed to read user store: {exc}") from exc

    def _fetch_all(self, sql: str, parameters: tuple) -> list[sqlite3.Row]:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchall()
        except sqlite3.Error as exc:
            raise UserStoreError(f"failed to read user store: {exc}") from exc


def _to_account(row: sqlite3.Row) -> UserAccount:
    return UserAccount(
        user_id=row["user_id"],
        username=row["username"],
        password_hash=row["password_hash"],
        display_name=row["display_name"],
        status=AccountStatus(row["status"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )
