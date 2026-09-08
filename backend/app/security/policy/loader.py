"""Loads the security policy document that drives clearance and privacy decisions.

One document, two policies: clearance ordering and privacy masking. Loading is
explicit so policy can be swapped per environment/test without touching code.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings
from app.security.clearance.policy import ClearancePolicy
from app.security.privacy.policy import PrivacyPolicy

_BACKEND_ROOT = Path(__file__).resolve().parents[3]


class SecurityPolicyError(Exception):
    """Raised when the policy document cannot be read or parsed."""


@dataclass(frozen=True)
class SecurityPolicy:
    clearance: ClearancePolicy
    privacy: PrivacyPolicy
    schema_version: int


def resolve_policy_path(path: str | Path | None = None) -> Path:
    """Resolve a policy path; relative paths are anchored to the backend root."""
    candidate = Path(path if path is not None else settings.CLEARANCE_POLICY_PATH)
    return candidate if candidate.is_absolute() else _BACKEND_ROOT / candidate


def load_security_policy(path: str | Path | None = None) -> SecurityPolicy:
    policy_path = resolve_policy_path(path)
    try:
        document = json.loads(policy_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SecurityPolicyError(f"security policy not found at {policy_path}") from exc
    except json.JSONDecodeError as exc:
        raise SecurityPolicyError(f"security policy at {policy_path} is not valid JSON") from exc

    if not isinstance(document, dict):
        raise SecurityPolicyError(f"security policy at {policy_path} must be a JSON object")

    return SecurityPolicy(
        clearance=ClearancePolicy.from_dict(document.get("clearance", {})),
        privacy=PrivacyPolicy.from_dict(document.get("privacy", {})),
        schema_version=int(document.get("schema_version", 1)),
    )
