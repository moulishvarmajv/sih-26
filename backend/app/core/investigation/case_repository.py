"""CaseRepository contract.

Minimal on purpose: a case must be resolvable before evidence can be authorized,
because its agency and security level are authorization inputs. Everything else
about investigations belongs to a later phase.
"""
from __future__ import annotations

from typing import Protocol

from app.core.domain.case import Case


class CaseRepositoryError(Exception):
    """Raised when case state cannot be read or written."""


class CaseRepository(Protocol):
    def create(self, case: Case) -> Case: ...

    def get(self, case_id: str) -> Case | None: ...
