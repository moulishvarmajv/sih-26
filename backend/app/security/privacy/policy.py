"""Privacy/masking policy.

Masking is part of authorization, not a presentation concern: when a caller may
see a resource but not its identifying fields, the decision is PARTIAL and names
the fields that must be withheld. Field *names* are safe to return and audit;
field *values* are not.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


class PrivacyPolicyError(Exception):
    """Raised when a privacy policy document is invalid."""


@dataclass(frozen=True)
class PrivacyPolicy:
    unmask_minimum_level: str
    maskable_fields: frozenset[str]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PrivacyPolicy:
        unmask_minimum_level = data.get("unmask_minimum_level")
        if not isinstance(unmask_minimum_level, str):
            raise PrivacyPolicyError("privacy policy requires 'unmask_minimum_level'")

        raw_fields = data.get("maskable_fields", [])
        if not isinstance(raw_fields, list) or not all(isinstance(f, str) for f in raw_fields):
            raise PrivacyPolicyError("'maskable_fields' must be a list of strings")

        return cls(
            unmask_minimum_level=unmask_minimum_level,
            maskable_fields=frozenset(raw_fields),
        )

    def fields_to_mask(self, resource_fields: Iterable[str]) -> tuple[str, ...]:
        """Return the sorted subset of `resource_fields` this policy treats as maskable."""
        return tuple(sorted(set(resource_fields) & self.maskable_fields))
