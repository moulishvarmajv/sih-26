"""EvidenceObjectStore contract.

Raw payloads live here; metadata and state live in the EvidenceRepository. The
store owns its own layout — callers pass logical key parts and receive an opaque
reference to persist, so no storage path is hard-coded anywhere else.
"""
from __future__ import annotations

from typing import Protocol


class ObjectStoreError(Exception):
    """Raised when a payload cannot be written or read."""


class EvidenceObjectStore(Protocol):
    def put(self, key: tuple[str, ...], payload: bytes) -> str:
        """Store bytes under a logical key and return the reference to keep."""
        ...

    def get(self, reference: str) -> bytes:
        """Read back a payload. Raises ObjectStoreError if it is missing."""
        ...

    def exists(self, reference: str) -> bool: ...
