"""Directory of known agencies.

Synthetic entries for the MVP. Agencies are eventually contributed by registered
plugins — this directory is the seam where that happens, so nothing above it
needs to change when plugins start declaring their own agency.

Membership lives in AccessGrantRepository; this only answers "does this agency
exist and what is it called".
"""
from __future__ import annotations

from typing import Protocol

from app.core.domain.agency import Agency

SYNTHETIC_AGENCIES: tuple[Agency, ...] = (
    Agency(id="POLICE", name="Police", plugin_id="police"),
    Agency(id="CYBER_CRIME", name="Cyber Crime", plugin_id="cybercrime"),
    Agency(id="FINANCIAL_CRIME", name="Financial Crime", plugin_id="financial_crime"),
)


class AgencyDirectory(Protocol):
    def get(self, agency_id: str) -> Agency | None:
        """Resolve an agency by id, or None if it is not a known agency."""
        ...

    def all(self) -> tuple[Agency, ...]:
        """Return every known agency."""
        ...


class InMemoryAgencyDirectory:
    def __init__(self, agencies: tuple[Agency, ...] = SYNTHETIC_AGENCIES) -> None:
        self._agencies = {agency.id: agency for agency in agencies}

    def get(self, agency_id: str) -> Agency | None:
        return self._agencies.get(agency_id)

    def all(self) -> tuple[Agency, ...]:
        return tuple(self._agencies.values())
