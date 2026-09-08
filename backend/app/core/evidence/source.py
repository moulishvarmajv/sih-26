"""EvidenceSource contract.

An EvidenceSource adapts one external data type (CDR export, FIR text dump,
bank statement, ...) into normalised records. Adapters do not assign evidence
ids, hashes or versions — ingestion does, so identity and integrity stay
consistent across every source.

Adapters must not perform authorization checks: that is the AuthorizationEngine's
job. They must be deterministic (same input, same output) and must reject
malformed input rather than guessing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol

from app.core.evidence.models import TrustClassification


class EvidenceSourceError(Exception):
    """Raised when source input is malformed and cannot be trusted."""


@dataclass(frozen=True)
class SourceEvidence:
    """One normalised record emitted by an adapter, before it becomes evidence."""

    source_record_id: str
    payload: Mapping[str, Any]
    classification: TrustClassification
    source_reference: str
    security_level: str | None = None
    sensitive_fields: tuple[str, ...] = ()


class EvidenceSource(Protocol):
    source_id: str

    def fetch(self, case_id: str) -> Iterable[SourceEvidence]:
        """Return the normalised records this source holds for a case.

        Raises EvidenceSourceError if the underlying input is malformed.
        """
        ...
