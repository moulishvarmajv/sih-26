"""EvidenceSource contract.

An EvidenceSource adapts one external data type (CDR export, FIR text dump,
bank statement, ...) into EvidenceRecord objects. Adapters must not perform
authorization checks themselves — that is the AuthorizationEngine's job.
"""
from __future__ import annotations

from typing import Iterable, Protocol

from app.core.evidence.models import EvidenceRecord


class EvidenceSource(Protocol):
    source_id: str

    def fetch(self, case_id: str) -> Iterable[EvidenceRecord]:
        """Return the evidence records this source currently holds for a case."""
        ...
