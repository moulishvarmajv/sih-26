"""IntegrityProvider contract for evidence tamper-detection.

`app.core.security` already provides SHA-256 hashing helpers; a concrete
IntegrityProvider implementation should wrap those rather than reimplementing
hashing, once evidence ingestion is built.
"""
from __future__ import annotations

from typing import Protocol


class IntegrityProvider(Protocol):
    def compute_hash(self, data: bytes) -> str:
        """Return a deterministic content hash for raw evidence bytes."""
        ...

    def verify(self, data: bytes, expected_hash: str) -> bool:
        """Return True if data's current hash matches the recorded hash."""
        ...
