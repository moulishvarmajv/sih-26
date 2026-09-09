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
    # Evidence lifecycle.
    EVIDENCE_VERSION_CREATED = "EVIDENCE_VERSION_CREATED"
    EVIDENCE_VIEWED = "EVIDENCE_VIEWED"
    EVIDENCE_ANALYSIS_STARTED = "EVIDENCE_ANALYSIS_STARTED"
    EVIDENCE_ANALYSIS_COMPLETED = "EVIDENCE_ANALYSIS_COMPLETED"
    EVIDENCE_ANALYSIS_FAILED = "EVIDENCE_ANALYSIS_FAILED"
    EVIDENCE_ANALYSIS_REUSED = "EVIDENCE_ANALYSIS_REUSED"
    EVIDENCE_REANALYZED = "EVIDENCE_REANALYZED"
    # Knowledge graph.
    GRAPH_INGESTION_STARTED = "GRAPH_INGESTION_STARTED"
    GRAPH_INGESTION_COMPLETED = "GRAPH_INGESTION_COMPLETED"
    GRAPH_INGESTION_FAILED = "GRAPH_INGESTION_FAILED"
    GRAPH_QUERY_EXECUTED = "GRAPH_QUERY_EXECUTED"
    GRAPH_ACCESS_ALLOWED = "GRAPH_ACCESS_ALLOWED"
    GRAPH_ACCESS_DENIED = "GRAPH_ACCESS_DENIED"
    # Entity resolution. ENTITY_MATCHED and ENTITY_CONFLICT above predate these
    # and stay reserved for findings; a resolution has its own lifecycle.
    ENTITY_RESOLUTION_STARTED = "ENTITY_RESOLUTION_STARTED"
    ENTITY_RESOLUTION_CANDIDATE_CREATED = "ENTITY_RESOLUTION_CANDIDATE_CREATED"
    ENTITY_RESOLUTION_AUTO_ACCEPTED = "ENTITY_RESOLUTION_AUTO_ACCEPTED"
    ENTITY_RESOLUTION_REVIEW_REQUIRED = "ENTITY_RESOLUTION_REVIEW_REQUIRED"
    ENTITY_RESOLUTION_UNRESOLVED = "ENTITY_RESOLUTION_UNRESOLVED"
    ENTITY_RESOLUTION_COMPLETED = "ENTITY_RESOLUTION_COMPLETED"
    ENTITY_RESOLUTION_APPROVED = "ENTITY_RESOLUTION_APPROVED"
    ENTITY_RESOLUTION_REJECTED = "ENTITY_RESOLUTION_REJECTED"
    ENTITY_RESOLUTION_DEFERRED = "ENTITY_RESOLUTION_DEFERRED"
    ENTITY_RESOLUTION_SUPERSEDED = "ENTITY_RESOLUTION_SUPERSEDED"
    ENTITY_RESOLUTION_PROJECTED = "ENTITY_RESOLUTION_PROJECTED"
    ENTITY_RESOLUTION_FAILED = "ENTITY_RESOLUTION_FAILED"
    ENTITY_RESOLUTION_ACCESS_DENIED = "ENTITY_RESOLUTION_ACCESS_DENIED"
    # Graph analytics. GRAPH_UPDATED above predates these and stays reserved for
    # ingestion; an analytics run reads the graph and never writes to it.
    ANALYTICS_STARTED = "ANALYTICS_STARTED"
    ANALYTICS_COMPLETED = "ANALYTICS_COMPLETED"
    ANALYTICS_FAILED = "ANALYTICS_FAILED"
    ANALYTICS_ACCESS_DENIED = "ANALYTICS_ACCESS_DENIED"
    SIGNAL_CREATED = "SIGNAL_CREATED"
    SIGNAL_REVISED = "SIGNAL_REVISED"


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
