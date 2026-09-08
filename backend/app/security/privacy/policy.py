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
    # Fields whose masked form keeps a recognisable suffix (e.g. a phone number,
    # so an investigator can still correlate calls). Everything else in
    # maskable_fields is redacted outright — which form applies is policy, never
    # a guess made from the value's shape.
    partial_mask_fields: frozenset[str] = frozenset()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PrivacyPolicy:
        unmask_minimum_level = data.get("unmask_minimum_level")
        if not isinstance(unmask_minimum_level, str):
            raise PrivacyPolicyError("privacy policy requires 'unmask_minimum_level'")

        maskable = _string_list(data, "maskable_fields")
        partial = _string_list(data, "partial_mask_fields")
        unknown = partial - maskable
        if unknown:
            raise PrivacyPolicyError(
                f"partial_mask_fields not listed as maskable: {sorted(unknown)}"
            )

        return cls(
            unmask_minimum_level=unmask_minimum_level,
            maskable_fields=maskable,
            partial_mask_fields=partial,
        )

    def fields_to_mask(self, resource_fields: Iterable[str]) -> tuple[str, ...]:
        """Return the sorted subset of `resource_fields` this policy treats as maskable."""
        return tuple(sorted(set(resource_fields) & self.maskable_fields))


def _string_list(data: Mapping[str, Any], key: str) -> frozenset[str]:
    raw = data.get(key, [])
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise PrivacyPolicyError(f"'{key}' must be a list of strings")
    return frozenset(raw)
