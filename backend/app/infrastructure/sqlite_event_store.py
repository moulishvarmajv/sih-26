"""SQLite-backed EventStore.

Append-only at the application layer: this class exposes no update or delete
method, and sequence/event ids are assigned here rather than accepted from
callers. It does not make the underlying file tamper-proof.

Payloads are serialised with sorted keys and compact separators so the stored
bytes for a given payload are deterministic.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from app.core.audit.event_store import (
    ActorType,
    EventDraft,
    EventStoreError,
    FlightRecorderEvent,
    StoredEvent,
)
from app.infrastructure.clock import utc_now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flight_recorder_events (
    sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id       TEXT    NOT NULL UNIQUE,
    event_type     TEXT    NOT NULL,
    occurred_at    TEXT    NOT NULL,
    case_id        TEXT,
    actor_id       TEXT,
    actor_type     TEXT    NOT NULL,
    correlation_id TEXT    NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    payload        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_case ON flight_recorder_events (case_id, sequence);
CREATE INDEX IF NOT EXISTS idx_events_type ON flight_recorder_events (event_type, sequence);
CREATE INDEX IF NOT EXISTS idx_events_actor ON flight_recorder_events (actor_id, sequence);
CREATE INDEX IF NOT EXISTS idx_events_time ON flight_recorder_events (occurred_at);
"""

_SELECT = """
SELECT sequence, event_id, event_type, occurred_at, case_id, actor_id,
       actor_type, correlation_id, schema_version, payload
FROM flight_recorder_events
"""


def _serialize(payload: Mapping[str, Any]) -> str:
    if not isinstance(payload, Mapping):
        raise EventStoreError("event payload must be a mapping")
    try:
        return json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise EventStoreError(f"event payload is not JSON-serialisable: {exc}") from exc


class SQLiteEventStore:
    """Local, append-only flight recorder backed by a single SQLite database."""

    def __init__(self, database_path: str | Path, clock: Callable[[], str] = utc_now_iso) -> None:
        self._clock = clock
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

    def append(self, draft: EventDraft) -> StoredEvent:
        event_id = uuid.uuid4().hex
        occurred_at = self._clock()
        payload_json = _serialize(draft.payload)

        try:
            with self._lock, self._connection:
                cursor = self._connection.execute(
                    """
                    INSERT INTO flight_recorder_events (
                        event_id, event_type, occurred_at, case_id, actor_id,
                        actor_type, correlation_id, schema_version, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        draft.event_type.value,
                        occurred_at,
                        draft.case_id,
                        draft.actor_id,
                        draft.actor_type.value,
                        draft.correlation_id,
                        1,
                        payload_json,
                    ),
                )
                sequence = int(cursor.lastrowid)
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to append event: {exc}") from exc

        return StoredEvent(
            event_id=event_id,
            sequence=sequence,
            event_type=draft.event_type,
            occurred_at=occurred_at,
            case_id=draft.case_id,
            actor_id=draft.actor_id,
            actor_type=draft.actor_type,
            correlation_id=draft.correlation_id,
            payload=MappingProxyType(dict(draft.payload)),
        )

    def get(self, event_id: str) -> StoredEvent | None:
        row = self._query_one(f"{_SELECT} WHERE event_id = ?", (event_id,))
        return None if row is None else _to_event(row)

    def list_for_case(self, case_id: str) -> list[StoredEvent]:
        return self._query_many(f"{_SELECT} WHERE case_id = ? ORDER BY sequence ASC", (case_id,))

    def list_for_user(self, user_id: str) -> list[StoredEvent]:
        return self._query_many(f"{_SELECT} WHERE actor_id = ? ORDER BY sequence ASC", (user_id,))

    def list_by_type(self, event_type: FlightRecorderEvent) -> list[StoredEvent]:
        return self._query_many(
            f"{_SELECT} WHERE event_type = ? ORDER BY sequence ASC", (event_type.value,)
        )

    def _query_one(self, sql: str, parameters: tuple[Any, ...]) -> sqlite3.Row | None:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchone()
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to read events: {exc}") from exc

    def _query_many(self, sql: str, parameters: tuple[Any, ...]) -> list[StoredEvent]:
        try:
            with self._lock:
                rows = self._connection.execute(sql, parameters).fetchall()
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to read events: {exc}") from exc
        return [_to_event(row) for row in rows]


def _to_event(row: sqlite3.Row) -> StoredEvent:
    return StoredEvent(
        event_id=row["event_id"],
        sequence=int(row["sequence"]),
        event_type=FlightRecorderEvent(row["event_type"]),
        occurred_at=row["occurred_at"],
        case_id=row["case_id"],
        actor_id=row["actor_id"],
        actor_type=ActorType(row["actor_type"]),
        correlation_id=row["correlation_id"],
        payload=MappingProxyType(json.loads(row["payload"])),
        schema_version=int(row["schema_version"]),
    )
