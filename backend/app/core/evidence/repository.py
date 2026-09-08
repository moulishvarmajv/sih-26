"""EvidenceRepository contract.

Persistence only. No authorization logic lives here — callers must already hold
an AuthorizationDecision before asking for anything, and no route may reach
these methods directly.

Superseding rules the implementation owns:
- creating a version marks the previous CURRENT version SUPERSEDED, and results
  computed from it STALE (they remain readable and auditable);
- storing a CURRENT result marks the previous CURRENT result for the same
  (evidence, task_type) SUPERSEDED.
"""
from __future__ import annotations

from typing import Protocol

from app.core.evidence.models import (
    AnalysisResult,
    EvidenceRecord,
    EvidenceVersion,
    ProcessingRun,
    ResultState,
    RunStatus,
)


class EvidenceRepositoryError(Exception):
    """Raised when evidence state cannot be read or written."""


class EvidenceRepository(Protocol):
    def create_evidence(self, record: EvidenceRecord) -> EvidenceRecord:
        """Persist a new logical evidence item."""
        ...

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None: ...

    def list_evidence_for_case(self, case_id: str) -> list[EvidenceRecord]: ...

    def create_version(self, version: EvidenceVersion) -> EvidenceVersion:
        """Persist a new version, superseding the previous current one."""
        ...

    def get_version(self, version_id: str) -> EvidenceVersion | None: ...

    def get_latest_version(self, evidence_id: str) -> EvidenceVersion | None: ...

    def list_versions(self, evidence_id: str) -> list[EvidenceVersion]:
        """Return every version, oldest first."""
        ...

    def create_run(self, run: ProcessingRun) -> ProcessingRun: ...

    def finish_run(
        self,
        run_id: str,
        status: RunStatus,
        completed_at: str,
        output_hash: str | None = None,
        error_code: str | None = None,
    ) -> ProcessingRun: ...

    def get_run(self, run_id: str) -> ProcessingRun | None: ...

    def save_result(self, result: AnalysisResult) -> AnalysisResult:
        """Persist a result, superseding the previous current one for this task type."""
        ...

    def get_current_result(self, evidence_id: str, task_type: str) -> AnalysisResult | None:
        """Return the CURRENT result for a task type, or None — never a stale or failed one."""
        ...

    def list_results(self, evidence_id: str) -> list[AnalysisResult]:
        """Return every result for this evidence, oldest first."""
        ...

    def mark_result_state(self, result_id: str, state: ResultState) -> None:
        """Explicit invalidation hook (e.g. an upstream FIR changed)."""
        ...
