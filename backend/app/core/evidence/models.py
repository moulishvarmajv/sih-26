"""Evidence domain model.

Four levels, deliberately separate so provenance survives reprocessing:

    EvidenceRecord   the logical item ("this CDR export")
    EvidenceVersion  one concrete content version of it, with its own hash
    ProcessingRun    one execution that processed one version
    AnalysisResult   what a run produced

A new analysis never overwrites history: it creates a new run and a new result,
and the previous result is retained as SUPERSEDED or STALE.

Two independent axes on evidence:

- `classification` is the *trust* axis (where the fact came from). Permanent —
  OBSERVED / DERIVED / INFERRED / GENERATED are never silently upgraded.
- `security_level` is the *access* axis (a clearance level code). Feeds
  authorization, never trust.

`sensitive_fields` names identifying fields a privacy policy may require to be
masked; it holds field names, never values.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TrustClassification(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    GENERATED = "GENERATED"


class EvidenceState(str, Enum):
    DISCOVERED = "DISCOVERED"
    INGESTED = "INGESTED"
    NORMALIZED = "NORMALIZED"
    AVAILABLE = "AVAILABLE"
    ARCHIVED = "ARCHIVED"


class VersionState(str, Enum):
    CURRENT = "CURRENT"
    SUPERSEDED = "SUPERSEDED"


class ResultState(str, Enum):
    CURRENT = "CURRENT"
    STALE = "STALE"          # the version it was computed from was superseded
    SUPERSEDED = "SUPERSEDED"  # a newer result replaced it
    FAILED = "FAILED"


class RunStatus(str, Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class EvidenceRecord:
    id: str
    case_id: str
    source_id: str
    source_record_id: str
    classification: TrustClassification
    state: EvidenceState
    created_at: str
    security_level: str | None = None  # None falls back to the policy default (fail closed)
    sensitive_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidenceVersion:
    version_id: str
    evidence_id: str
    version_number: int
    content_hash: str  # SHA-256 of the canonical payload bytes
    payload_ref: str  # opaque object-store reference; not a filesystem path to callers
    source_reference: str
    ingested_at: str
    state: VersionState = VersionState.CURRENT


@dataclass(frozen=True)
class ProcessingRun:
    run_id: str
    evidence_id: str
    evidence_version_id: str
    task_type: str
    status: RunStatus
    started_at: str
    workflow_version: str
    rule_version: str
    input_hash: str
    correlation_id: str
    completed_at: str | None = None
    output_hash: str | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class AnalysisResult:
    result_id: str
    run_id: str
    evidence_id: str
    evidence_version_id: str
    task_type: str
    classification: TrustClassification
    state: ResultState
    output_hash: str | None
    created_at: str
    payload_ref: str | None = None  # absent for FAILED results
