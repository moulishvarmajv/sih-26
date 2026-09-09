"""ResolutionRepository contract.

Persistence only. No scoring, no policy, no authorization: callers already hold
an AuthorizationDecision before anything here is reached, and no route touches
these methods directly.

The supersede rule the implementation owns, mirroring the evidence repository:
storing a decision for a lineage that already has a live one marks the previous
decision SUPERSEDED and links it forward. Nothing is deleted or rewritten, so
what the system believed at any point stays reconstructable — including the
decisions a person made and a later run replaced.

Reviews are append-only. A resolution's review history is the record of who
looked at it and when, and it survives supersession of the decision itself.
"""
from __future__ import annotations

from typing import Protocol, Sequence

from app.core.resolution.models import (
    EntityResolutionCandidate,
    EntityResolutionDecision,
    ResolutionReview,
    ResolutionStatus,
)


class ResolutionRepositoryError(Exception):
    """Raised when resolution state cannot be read or written."""


class ResolutionRepository(Protocol):
    def save_candidate(self, candidate: EntityResolutionCandidate) -> EntityResolutionCandidate:
        """Persist a candidate. Re-saving the same candidate id is a no-op."""
        ...

    def get_candidate(self, candidate_id: str) -> EntityResolutionCandidate | None: ...

    def list_candidates(self, case_id: str) -> list[EntityResolutionCandidate]: ...

    def save_decision(self, decision: EntityResolutionDecision) -> EntityResolutionDecision:
        """Persist a decision, superseding the previous live one for its lineage."""
        ...

    def get_decision(self, resolution_id: str) -> EntityResolutionDecision | None: ...

    def get_live_decision(self, lineage_id: str) -> EntityResolutionDecision | None:
        """Return the current decision for a lineage, or None — never a superseded one."""
        ...

    def list_decisions(
        self, case_id: str, statuses: Sequence[ResolutionStatus] | None = None
    ) -> list[EntityResolutionDecision]:
        """Return a case's decisions, including superseded ones unless filtered."""
        ...

    def list_lineage(self, lineage_id: str) -> list[EntityResolutionDecision]:
        """Return every version for one lineage, oldest first."""
        ...

    def update_status(
        self,
        resolution_id: str,
        status: ResolutionStatus,
        decided_at: str,
        decided_by: str,
        decision_actor: str,
        decision_reason: str | None = None,
    ) -> EntityResolutionDecision:
        """Record a terminal outcome on a decision that is still open."""
        ...

    def add_review(self, review: ResolutionReview) -> ResolutionReview:
        """Append one human action. Reviews are never edited or removed."""
        ...

    def list_reviews(self, resolution_id: str) -> list[ResolutionReview]:
        """Return a resolution's review history, oldest first."""
        ...
