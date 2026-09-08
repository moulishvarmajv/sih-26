"""Applies the masking a PARTIAL AuthorizationDecision names.

One implementation, used by every service that returns a payload — routes must
never mask by hand, and a client must never receive the raw value with an
instruction to hide it.

Which fields keep a recognisable suffix (`+919876543210` -> `+91-XXXX-3210`, so
calls can still be correlated) and which are redacted outright is decided by the
privacy policy, not inferred from what a value looks like: an IMEI and a phone
number are both long digit strings, and guessing would leak one of them.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

REDACTED = "***"

_DIGITS = re.compile(r"\d")


def mask_value(value: Any, keep_suffix: bool = False) -> Any:
    """Return the masked form of one value."""
    if keep_suffix and isinstance(value, str):
        digits = "".join(_DIGITS.findall(value))
        if len(digits) >= 4:
            prefix = f"+{digits[:2]}" if value.strip().startswith("+") else "XX"
            return f"{prefix}-XXXX-{digits[-4:]}"
    return REDACTED


def mask_payload(
    payload: Mapping[str, Any],
    fields: Iterable[str],
    partial_fields: Iterable[str] = (),
) -> dict[str, Any]:
    """Return a copy of `payload` with the named fields masked.

    Fields that are absent are ignored: the mask list comes from policy and may
    name fields this particular payload does not carry.
    """
    targets = set(fields)
    partial = set(partial_fields) & targets
    return {
        key: (mask_value(value, keep_suffix=key in partial) if key in targets else value)
        for key, value in payload.items()
    }
