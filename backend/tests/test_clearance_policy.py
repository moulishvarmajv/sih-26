"""Clearance/privacy policy is data-driven and rejects malformed documents."""
import json

import pytest

from app.security.clearance.policy import ClearancePolicyError, UnknownClearanceLevel
from app.security.policy.loader import SecurityPolicyError, load_security_policy


def test_shipped_policy_defines_l1_l2_l3():
    policy = load_security_policy()

    levels = policy.clearance.levels
    assert [levels[code].name for code in ("L1", "L2", "L3")] == [
        "INTERNAL",
        "CONFIDENTIAL",
        "RESTRICTED",
    ]


def test_clearance_comparison_uses_policy_rank():
    clearance = load_security_policy().clearance

    assert clearance.satisfies("L2", "L1")
    assert clearance.satisfies("L2", "L2")
    assert not clearance.satisfies("L2", "L3")


def test_unknown_level_raises():
    clearance = load_security_policy().clearance

    assert not clearance.knows("L9")
    with pytest.raises(UnknownClearanceLevel):
        clearance.rank("L9")


def test_missing_required_level_falls_back_to_fail_closed_default():
    clearance = load_security_policy().clearance

    assert clearance.required_or_default(None) == clearance.default_required_level
    assert clearance.required_or_default("L1") == "L1"


def test_privacy_policy_returns_sorted_maskable_intersection():
    privacy = load_security_policy().privacy

    masked = privacy.fields_to_mask(("tower_id", "subscriber_name", "account_number"))

    assert masked == ("account_number", "subscriber_name")


def test_missing_policy_file_raises(tmp_path):
    with pytest.raises(SecurityPolicyError):
        load_security_policy(tmp_path / "absent.json")


def test_policy_with_undefined_default_level_is_rejected(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "clearance": {
                    "levels": [{"code": "L1", "name": "INTERNAL", "rank": 1}],
                    "default_required_level": "L7",
                },
                "privacy": {"unmask_minimum_level": "L1", "maskable_fields": []},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ClearancePolicyError):
        load_security_policy(path)
