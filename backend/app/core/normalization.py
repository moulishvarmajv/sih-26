"""Deterministic canonical normalization shared by graph mapping and resolution.

Normalization is *formatting* only. It decides that two spellings of one value
are the same string; it never decides that two different values denote the same
entity — that is entity resolution, and it happens in `app.core.resolution`
behind an explicit, auditable decision.

Concretely: `+91 98 1234 5678` and `919812345678` canonicalise to the same
digits, so both key the same phone. A number written without a country code
keys a *different* value than one with it, because assuming a country would be
an inference, not a reformatting.

Every caller keeps the raw value it started from; nothing here is destructive to
provenance.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher

_NON_DIGITS = re.compile(r"\D")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_WHITESPACE = re.compile(r"\s+")


class NormalizationError(ValueError):
    """Raised when a value cannot be canonicalised without guessing at it."""


def canonical_phone(raw: str) -> str:
    """Digits only. No country code is ever added or removed."""
    digits = _NON_DIGITS.sub("", raw or "")
    if not digits:
        raise NormalizationError(f"cannot canonicalise phone number {raw!r}")
    return digits


def canonical_identifier(raw: str, kind: str = "identifier") -> str:
    """Upper-case, separator-free form for controlled identifiers (IMEI, account, ref)."""
    collapsed = _NON_ALNUM.sub("", (raw or "").lower())
    if not collapsed:
        raise NormalizationError(f"cannot canonicalise {kind} {raw!r}")
    return collapsed.upper()


def normalized_text(raw: str) -> str:
    """Lower-cased, punctuation-stripped, single-spaced."""
    lowered = _NON_ALNUM.sub(" ", (raw or "").lower())
    return _WHITESPACE.sub(" ", lowered).strip()


def name_tokens(raw: str) -> tuple[str, ...]:
    """Sorted tokens, so word order does not change identity of a written name."""
    return tuple(sorted(token for token in normalized_text(raw).split() if token))


def comparable_name(raw: str) -> str:
    """Canonical comparison form of a personal name."""
    return " ".join(name_tokens(raw))


def comparable_address(raw: str) -> str:
    """Canonical comparison form of an address."""
    return " ".join(name_tokens(raw))


def similarity(left: str, right: str) -> float:
    """Deterministic string similarity in [0.0, 1.0].

    `difflib.SequenceMatcher` over already-canonicalised text: stdlib only, no
    model, no training data, and the same pair always yields the same ratio.
    """
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()
