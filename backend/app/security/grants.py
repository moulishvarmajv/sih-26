"""Access grants: which agencies and cases a user has been granted, and need-to-know.

Grants are *data*, not policy — this module answers "what was granted" and never
"is this allowed". The AuthorizationEngine decides.

The in-memory implementation is the real store for this phase; a persisted one
replaces it behind the same protocol without touching policy or service code.
"""
from __future__ import annotations

from typing import Protocol


class AccessGrantRepository(Protocol):
    def agencies_for_user(self, user_id: str) -> frozenset[str]:
        """Return the agency ids this user may operate in."""
        ...

    def cases_for_user(self, user_id: str, agency_id: str) -> frozenset[str]:
        """Return the case ids this user may access within an agency."""
        ...

    def has_need_to_know(self, user_id: str, case_id: str) -> bool:
        """Return whether the user has a recorded need-to-know for this case."""
        ...


class InMemoryAccessGrantRepository:
    def __init__(self) -> None:
        self._agencies: dict[str, set[str]] = {}
        self._cases: dict[tuple[str, str], set[str]] = {}
        self._need_to_know: set[tuple[str, str]] = set()

    def grant_agency(self, user_id: str, agency_id: str) -> None:
        self._agencies.setdefault(user_id, set()).add(agency_id)

    def grant_case(
        self, user_id: str, agency_id: str, case_id: str, need_to_know: bool = True
    ) -> None:
        self._cases.setdefault((user_id, agency_id), set()).add(case_id)
        if need_to_know:
            self._need_to_know.add((user_id, case_id))

    def revoke_case(self, user_id: str, agency_id: str, case_id: str) -> None:
        self._cases.get((user_id, agency_id), set()).discard(case_id)
        self._need_to_know.discard((user_id, case_id))

    def agencies_for_user(self, user_id: str) -> frozenset[str]:
        return frozenset(self._agencies.get(user_id, ()))

    def cases_for_user(self, user_id: str, agency_id: str) -> frozenset[str]:
        return frozenset(self._cases.get((user_id, agency_id), ()))

    def has_need_to_know(self, user_id: str, case_id: str) -> bool:
        return (user_id, case_id) in self._need_to_know
