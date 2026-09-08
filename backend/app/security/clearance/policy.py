"""Clearance levels expressed as policy data, not as hard-coded business logic.

Level codes ("L1", "L2", ...), their display names and their ordering all come
from the configured policy document. Business logic asks this policy whether one
level satisfies another; it must never compare level strings directly.

Holding a clearance never grants access on its own — the AuthorizationEngine
combines it with agency, case, need-to-know, role and privacy policy.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


class ClearancePolicyError(Exception):
    """Raised when a clearance policy document is invalid."""


class UnknownClearanceLevel(ClearancePolicyError):
    """Raised when a level code is not defined by the active policy."""


@dataclass(frozen=True)
class ClearanceLevelSpec:
    code: str
    name: str
    rank: int


@dataclass(frozen=True)
class ClearancePolicy:
    levels: Mapping[str, ClearanceLevelSpec]
    default_required_level: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ClearancePolicy:
        raw_levels = data.get("levels")
        if not raw_levels:
            raise ClearancePolicyError("clearance policy defines no levels")

        levels: dict[str, ClearanceLevelSpec] = {}
        for entry in raw_levels:
            try:
                spec = ClearanceLevelSpec(
                    code=entry["code"], name=entry["name"], rank=int(entry["rank"])
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ClearancePolicyError(f"invalid clearance level entry: {entry!r}") from exc
            if spec.code in levels:
                raise ClearancePolicyError(f"duplicate clearance level code '{spec.code}'")
            levels[spec.code] = spec

        default_required = data.get("default_required_level")
        if default_required not in levels:
            raise ClearancePolicyError(
                f"default_required_level '{default_required}' is not a defined level"
            )

        return cls(
            levels=MappingProxyType(levels),
            default_required_level=default_required,
        )

    def knows(self, code: str | None) -> bool:
        return code in self.levels

    def rank(self, code: str) -> int:
        try:
            return self.levels[code].rank
        except KeyError as exc:
            raise UnknownClearanceLevel(f"unknown clearance level '{code}'") from exc

    def satisfies(self, held: str, required: str) -> bool:
        """Return True if `held` is at least as high as `required`."""
        return self.rank(held) >= self.rank(required)

    def required_or_default(self, declared: str | None) -> str:
        """Resolve a resource's declared level, falling back to the fail-closed default."""
        return declared if declared is not None else self.default_required_level
