"""EvidenceDebtRepository contract.

Persistence only. No detection, no policy, no authorization: callers already
hold an AuthorizationDecision before anything here is reached, and no route
touches these methods directly.

Two rules the implementation owns, mirroring evidence, resolution and analytics:

- **saving an item whose facts changed supersedes the previous version and
  keeps it**, so what the engine concluded at any point stays reconstructable;
- **saving an item whose facts are unchanged is a no-op**, so a recalculation
  over unchanged investigation state manufactures no new debt.

Every record is addressed by `(debt_id, scope_fingerprint)` rather than by
`debt_id` alone, and that is a security property rather than a schema detail.
Debt is computed over the evidence one reader is authorized for, so a snapshot
or an item only means something alongside the scope it was computed in — and
keying on it is what stops a narrow reader from reading a cleared reader's
totals, comparing a trend against them, or closing a gap they cannot see.
Snapshots are append-only.
"""
from __future__ import annotations

from typing import Protocol, Sequence

from app.core.debt.models import (
    DebtCategory,
    DebtStatus,
    EvidenceDebtItem,
    EvidenceDebtSnapshot,
)


class EvidenceDebtRepositoryError(Exception):
    """Raised when evidence-debt state cannot be read or written."""


class EvidenceDebtRepository(Protocol):
    # -- snapshots --------------------------------------------------------

    def save_snapshot(self, snapshot: EvidenceDebtSnapshot) -> EvidenceDebtSnapshot:
        """Append one calculation. Never overwrites an earlier snapshot."""
        ...

    def get_snapshot(self, snapshot_id: str) -> EvidenceDebtSnapshot | None: ...

    def latest_snapshot(
        self, case_id: str, scope_fingerprint: str
    ) -> EvidenceDebtSnapshot | None:
        """The most recent snapshot for a case *within one authorized scope*."""
        ...

    def list_snapshots(
        self, case_id: str, scope_fingerprint: str | None = None
    ) -> list[EvidenceDebtSnapshot]:
        """A case's snapshots, oldest first."""
        ...

    # -- items ------------------------------------------------------------

    def save_item(self, item: EvidenceDebtItem) -> EvidenceDebtItem:
        """Persist an item, superseding the previous version when the facts changed.

        Returns the stored record — which is the *existing* one, unchanged, when
        the incoming facts match it.
        """
        ...

    def get_item(self, debt_id: str, scope_fingerprint: str) -> EvidenceDebtItem | None:
        """The live version of one item within one scope, or None."""
        ...

    def list_items(
        self,
        case_id: str,
        categories: Sequence[DebtCategory] | None = None,
        statuses: Sequence[DebtStatus] | None = None,
        scope_fingerprint: str | None = None,
    ) -> list[EvidenceDebtItem]:
        """Live items for a case, highest contribution first."""
        ...

    def list_item_history(
        self, debt_id: str, scope_fingerprint: str
    ) -> list[EvidenceDebtItem]:
        """Every version recorded for one debt identity in one scope, oldest first."""
        ...

    def update_item_status(
        self,
        debt_id: str,
        scope_fingerprint: str,
        status: DebtStatus,
        changed_at: str,
        changed_by: str,
        reason: str | None = None,
    ) -> EvidenceDebtItem:
        """Record a lifecycle transition on the live version. Deletes nothing."""
        ...
