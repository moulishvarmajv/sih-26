"""EventStore contract for the Flight Recorder (local, event-driven audit log).

Callers construct an `EventDraft`; the store assigns identity, ordering and
timestamp and returns a `StoredEvent`. Sequence numbers cannot be forged by
callers, and the interface exposes no update or delete operation — the log is
append-only at the application layer.

This is *not* a claim of cryptographic immutability: the underlying storage is
still writable by anything with filesystem access. Tamper-evidence comes later.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol


class EventStoreError(Exception):
    """Raised when an event cannot be recorded or read back."""


class ActorType(str, Enum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    PLUGIN = "PLUGIN"


class FlightRecorderEvent(str, Enum):
    CASE_CREATED = "CASE_CREATED"
    TASK_STARTED = "TASK_STARTED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"
    TASK_RETRIED = "TASK_RETRIED"
    EVIDENCE_CREATED = "EVIDENCE_CREATED"
    ENTITY_MATCHED = "ENTITY_MATCHED"
    ENTITY_CONFLICT = "ENTITY_CONFLICT"
    GRAPH_UPDATED = "GRAPH_UPDATED"
    FINDING_CREATED = "FINDING_CREATED"
    FINDING_REVISED = "FINDING_REVISED"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    HUMAN_REJECTED = "HUMAN_REJECTED"
    NEXT_ACTION_RECOMMENDED = "NEXT_ACTION_RECOMMENDED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    LOGIN = "LOGIN"
    CLEARANCE_VERIFIED = "CLEARANCE_VERIFIED"
    AGENCY_CONTEXT_SWITCHED = "AGENCY_CONTEXT_SWITCHED"
    EVIDENCE_ACCESS_ALLOWED = "EVIDENCE_ACCESS_ALLOWED"
    EVIDENCE_ACCESS_DENIED = "EVIDENCE_ACCESS_DENIED"
    EVIDENCE_REDACTED = "EVIDENCE_REDACTED"
    ACCESS_REQUEST_CREATED = "ACCESS_REQUEST_CREATED"
    ACCESS_REQUEST_APPROVED = "ACCESS_REQUEST_APPROVED"
    ACCESS_REQUEST_REVOKED = "ACCESS_REQUEST_REVOKED"
    # Denial/decision counterparts, so every authentication and authorization
    # outcome is auditable.
    LOGIN_FAILED = "LOGIN_FAILED"
    AGENCY_CONTEXT_DENIED = "AGENCY_CONTEXT_DENIED"
    CASE_ACCESS_ALLOWED = "CASE_ACCESS_ALLOWED"
    CASE_ACCESS_DENIED = "CASE_ACCESS_DENIED"
    ACTION_ALLOWED = "ACTION_ALLOWED"
    ACTION_DENIED = "ACTION_DENIED"


@dataclass(frozen=True)
class EventDraft:
    event_type: FlightRecorderEvent
    actor_id: str | None
    actor_type: ActorType
    correlation_id: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    case_id: str | None = None


@dataclass(frozen=True)
class StoredEvent:
    event_id: str
    sequence: int
    event_type: FlightRecorderEvent
    occurred_at: str
    actor_id: str | None
    actor_type: ActorType
    correlation_id: str
    payload: Mapping[str, Any]
    case_id: str | None = None
    schema_version: int = 1


class EventStore(Protocol):
    def append(self, draft: EventDraft) -> StoredEvent:
        """Record one event and return it with its assigned id, sequence and timestamp."""
        ...

    def get(self, event_id: str) -> StoredEvent | None:
        """Return one event by id, or None if it does not exist."""
        ...

    def list_for_case(self, case_id: str) -> list[StoredEvent]:
        """Return a case's events in append order."""
        ...

    def list_for_user(self, user_id: str) -> list[StoredEvent]:
        """Return events attributed to an actor, in append order."""
        ...

    def list_by_type(self, event_type: FlightRecorderEvent) -> list[StoredEvent]:
        """Return events of one type, in append order."""
        ...
