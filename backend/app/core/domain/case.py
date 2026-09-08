"""Domain contract for an investigation case."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Case:
    id: str
    agency_id: str
    title: str
    status: str  # e.g. OPEN, CLOSED, ARCHIVED — formalized when the investigation module lands
    security_level: str | None = None  # clearance level code; None falls back to the policy default
