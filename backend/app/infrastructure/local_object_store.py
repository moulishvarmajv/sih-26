"""Local filesystem evidence object store.

Layout, owned entirely by this class:

    <root>/CASE-001/EV-001/v1/source.json

Key parts are validated before they touch the filesystem: a part that is empty,
absolute, or contains a separator or `..` is rejected, so an identifier that
reaches here from a source adapter cannot escape the root.
"""
from __future__ import annotations

import re
from pathlib import Path

from app.core.evidence.object_store import ObjectStoreError

_SAFE_PART = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _validate(key: tuple[str, ...]) -> tuple[str, ...]:
    if not key:
        raise ObjectStoreError("object key must have at least one part")
    for part in key:
        if not _SAFE_PART.match(part) or part in (".", ".."):
            raise ObjectStoreError(f"unsafe object key part: {part!r}")
    return key


class LocalFileEvidenceObjectStore:
    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def put(self, key: tuple[str, ...], payload: bytes) -> str:
        reference = "/".join(_validate(key))
        path = self._path_for(reference)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        except OSError as exc:
            raise ObjectStoreError(f"failed to write {reference}: {exc}") from exc
        return reference

    def get(self, reference: str) -> bytes:
        path = self._path_for(reference)
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ObjectStoreError(f"failed to read {reference}: {exc}") from exc

    def exists(self, reference: str) -> bool:
        return self._path_for(reference).is_file()

    def _path_for(self, reference: str) -> Path:
        parts = _validate(tuple(reference.split("/")))
        return self._root.joinpath(*parts)
