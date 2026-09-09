"""AnalyticsRepository contract.

Persistence only. No metrics, no policy, no authorization: callers already hold
an AuthorizationDecision before anything here is reached, and no route touches
these methods directly.

The supersede rule the implementation owns, mirroring evidence and resolution:
saving a signal whose identity already has an ACTIVE record marks that record
SUPERSEDED and keeps it. A later run therefore shows what changed rather than
overwriting what the system previously reported — the same discipline that
applies to an analysis result and an identity decision applies to a signal.
"""
from __future__ import annotations

from typing import Protocol, Sequence

from app.core.analytics.models import AnalyticsRun, InvestigationSignal, SignalType


class AnalyticsRepositoryError(Exception):
    """Raised when analytics state cannot be read or written."""


class AnalyticsRepository(Protocol):
    def save_run(self, run: AnalyticsRun) -> AnalyticsRun:
        """Persist one execution and the scope it saw."""
        ...

    def get_run(self, run_id: str) -> AnalyticsRun | None: ...

    def list_runs(self, case_id: str) -> list[AnalyticsRun]:
        """Return a case's runs, oldest first."""
        ...

    def save_signal(self, signal: InvestigationSignal) -> InvestigationSignal:
        """Persist a signal, superseding the previous active one for its identity."""
        ...

    def get_signal(self, signal_id: str) -> InvestigationSignal | None: ...

    def list_signals(
        self,
        case_id: str,
        signal_types: Sequence[SignalType] | None = None,
        active_only: bool = True,
    ) -> list[InvestigationSignal]:
        """Return a case's signals, highest scoring first."""
        ...

    def list_signal_history(self, signal_id: str) -> list[InvestigationSignal]:
        """Every version recorded for one signal identity, oldest first."""
        ...
