"""Password hashing behind a protocol, so the algorithm is replaceable.

Uses stdlib scrypt: a memory-hard KDF with no extra dependency. Hashes are
self-describing (`scrypt$n$r$p$salt$hash`) so parameters can be raised later
without invalidating existing rows.

Verification is constant-time, and `dummy_verify` exists so callers can spend
the same work on an unknown username as on a real one — otherwise response
timing reveals which accounts exist.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Protocol

_SCHEME = "scrypt"
_N = 2**14
_R = 8
_P = 1
_SALT_BYTES = 16
_KEY_LEN = 32


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str:
        """Return an encoded hash that embeds the salt and parameters."""
        ...

    def verify(self, password: str, encoded: str) -> bool:
        """Return True if the password matches the encoded hash."""
        ...

    def dummy_verify(self, password: str) -> None:
        """Spend comparable work when no account exists, to equalise timing."""
        ...


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class ScryptPasswordHasher:
    def __init__(self, n: int = _N, r: int = _R, p: int = _P) -> None:
        self._n, self._r, self._p = n, r, p
        self._dummy = self.hash(secrets.token_urlsafe(16))

    def hash(self, password: str) -> str:
        salt = secrets.token_bytes(_SALT_BYTES)
        derived = self._derive(password, salt, self._n, self._r, self._p)
        return f"{_SCHEME}${self._n}${self._r}${self._p}${_b64(salt)}${_b64(derived)}"

    def verify(self, password: str, encoded: str) -> bool:
        try:
            scheme, n, r, p, salt_b64, hash_b64 = encoded.split("$")
            if scheme != _SCHEME:
                return False
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
            derived = self._derive(password, salt, int(n), int(r), int(p))
        except (ValueError, TypeError):
            return False
        return hmac.compare_digest(derived, expected)

    def dummy_verify(self, password: str) -> None:
        self.verify(password, self._dummy)

    def _derive(self, password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=_KEY_LEN
        )
