"""SQLite implementation of CaseRepository."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from app.core.domain.case import Case
from app.core.investigation.case_repository import CaseRepositoryError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id        TEXT PRIMARY KEY,
    agency_id      TEXT NOT NULL,
    title          TEXT NOT NULL,
    status         TEXT NOT NULL,
    security_level TEXT
);
"""


class SQLiteCaseRepository:
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

    def create(self, case: Case) -> Case:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO cases (case_id, agency_id, title, status, security_level) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (case.id, case.agency_id, case.title, case.status, case.security_level),
                )
        except sqlite3.IntegrityError as exc:
            raise CaseRepositoryError(f"case '{case.id}' already exists") from exc
        return case

    def get(self, case_id: str) -> Case | None:
        try:
            with self._lock:
                row = self._connection.execute(
                    "SELECT * FROM cases WHERE case_id = ?", (case_id,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise CaseRepositoryError(f"failed to read case: {exc}") from exc
        if row is None:
            return None
        return Case(
            id=row["case_id"],
            agency_id=row["agency_id"],
            title=row["title"],
            status=row["status"],
            security_level=row["security_level"],
        )
