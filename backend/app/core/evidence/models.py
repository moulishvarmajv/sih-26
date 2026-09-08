"""Domain contract for evidence records.

Two independent axes, deliberately not merged:

- `classification` is the *trust* axis (where the fact came from). It is
  permanent: OBSERVED, DERIVED, INFERRED and GENERATED evidence must never be
  silently reclassified into a higher-trust tier.
- `security_level` is the *access* axis (a clearance level code resolved against
  the active clearance policy). It feeds authorization, never trust.

`sensitive_fields` names the identifying fields a privacy policy may require to
be masked; it holds field names, never values.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class TrustClassification(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    GENERATED = "GENERATED"


@dataclass(frozen=True)
class EvidenceRecord:
    id: str
    case_id: str
    source_id: str
    classification: TrustClassification
    content_hash: str
    created_at: str
    security_level: str | None = None  # None falls back to the policy default (fail closed)
    sensitive_fields: tuple[str, ...] = ()
