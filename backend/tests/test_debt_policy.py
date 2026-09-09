"""The debt policy document, and the arithmetic it drives.

Weights and thresholds are data, so these tests read the shipped document and
then feed the loader deliberately broken ones. A policy that silently accepts an
unknown severity or a missing category would turn a configuration mistake into a
wrong number nobody could trace.
"""
import json

import pytest

from app.core.debt.models import DebtBand, DebtCategory, DebtSeverity
from app.core.debt.policy import (
    DebtPolicyError,
    EvidenceDebtPolicy,
    ExpectationKind,
    load_debt_policy,
)


@pytest.fixture
def policy():
    return load_debt_policy()


@pytest.fixture
def document():
    from app.core.debt.policy import resolve_policy_path

    return json.loads(resolve_policy_path().read_text(encoding="utf-8"))


# -- the shipped document ----------------------------------------------------


def test_the_shipped_policy_loads_and_names_its_version(policy):
    assert policy.policy_version
    assert policy.schema_version >= 1


def test_every_category_has_a_weight(policy):
    for category in DebtCategory:
        assert policy.category(category).weight > 0


def test_every_severity_has_a_multiplier(policy):
    multipliers = [policy.severity_multiplier(severity) for severity in DebtSeverity]

    assert multipliers == sorted(multipliers), "severity must be monotonic"


def test_every_band_is_defined_and_ordered(policy):
    bands = [threshold.band for threshold in policy.bands]

    assert set(bands) == set(DebtBand)
    assert bands == [DebtBand.CRITICAL, DebtBand.HIGH, DebtBand.MODERATE, DebtBand.LOW]


def test_expectations_are_explicit_and_named(policy):
    assert policy.expectations
    for expectation in policy.expectations:
        assert expectation.expectation_id
        assert expectation.when_source_present
        if expectation.kind is ExpectationKind.SOURCE_PRESENT:
            assert expectation.expected_source_id
        else:
            assert expectation.expected_task_type


def test_an_actionable_category_names_the_capability_it_needs(policy):
    """The integration boundary a Navigator will consume, recorded not acted on."""
    for category in DebtCategory:
        entry = policy.category(category)
        if entry.actionable:
            assert entry.required_capability
        assert entry.blocking_reason is not None


# -- the arithmetic ----------------------------------------------------------


@pytest.mark.parametrize(
    "normalized, expected",
    [
        (0.0, DebtBand.LOW),
        (0.24, DebtBand.LOW),
        (0.25, DebtBand.MODERATE),
        (0.49, DebtBand.MODERATE),
        (0.5, DebtBand.HIGH),
        (0.74, DebtBand.HIGH),
        (0.75, DebtBand.CRITICAL),
        (1.0, DebtBand.CRITICAL),
    ],
)
def test_bands_come_from_thresholds_not_from_code(policy, normalized, expected):
    assert policy.band_for(normalized) is expected


def test_normalization_saturates_and_never_exceeds_one(policy):
    assert policy.normalize(0.0) == 0.0
    assert policy.normalize(policy.normalization_saturates_at) == 1.0
    assert policy.normalize(policy.normalization_saturates_at * 10) == 1.0


def test_normalization_is_proportional_below_saturation(policy):
    half = policy.normalization_saturates_at / 2

    assert policy.normalize(half) == pytest.approx(0.5)


def test_scope_factor_rises_with_reach_and_holds_a_floor(policy):
    scope = policy.scope

    assert scope.factor(0) == scope.minimum_factor
    assert scope.factor(1) >= scope.minimum_factor
    assert scope.factor(scope.saturates_at) == 1.0
    assert scope.factor(scope.saturates_at * 5) == 1.0
    assert scope.factor(1) <= scope.factor(scope.saturates_at)


def test_relied_upon_evidence_weighs_more_than_evidence_nothing_uses(policy):
    assert policy.criticality.factor(True) > policy.criticality.factor(False)


# -- rejection of broken documents -------------------------------------------


def test_a_policy_without_a_version_is_rejected(document):
    document.pop("policy_version")

    with pytest.raises(DebtPolicyError, match="policy_version"):
        EvidenceDebtPolicy.from_dict(document)


def test_a_policy_missing_a_category_is_rejected(document):
    document["categories"].pop("STALE")

    with pytest.raises(DebtPolicyError, match="missing categories"):
        EvidenceDebtPolicy.from_dict(document)


def test_a_policy_missing_a_severity_multiplier_is_rejected(document):
    document["severity_multipliers"].pop("CRITICAL")

    with pytest.raises(DebtPolicyError, match="severity multipliers"):
        EvidenceDebtPolicy.from_dict(document)


def test_an_unknown_severity_is_rejected(document):
    document["stale"]["severity"] = "APOCALYPTIC"

    with pytest.raises(DebtPolicyError, match="unknown severity"):
        EvidenceDebtPolicy.from_dict(document)


def test_an_expectation_without_an_id_is_rejected(document):
    document["expectations"][0].pop("expectation_id")

    with pytest.raises(DebtPolicyError, match="expectation_id"):
        EvidenceDebtPolicy.from_dict(document)


def test_duplicate_expectation_ids_are_rejected(document):
    document["expectations"].append(dict(document["expectations"][0]))

    with pytest.raises(DebtPolicyError, match="duplicate expectation"):
        EvidenceDebtPolicy.from_dict(document)


def test_an_expectation_missing_what_it_expects_is_rejected(document):
    document["expectations"][0].pop("expected_source_id")

    with pytest.raises(DebtPolicyError, match="expected_source_id"):
        EvidenceDebtPolicy.from_dict(document)


def test_a_weak_trust_floor_without_a_severity_is_rejected(document):
    document["weak"]["severity_by_classification"].pop("INFERRED")

    with pytest.raises(DebtPolicyError, match="no severity"):
        EvidenceDebtPolicy.from_dict(document)


def test_a_policy_with_no_bands_is_rejected(document):
    document["bands"] = []

    with pytest.raises(DebtPolicyError, match="no bands"):
        EvidenceDebtPolicy.from_dict(document)


def test_a_missing_policy_file_is_reported_clearly(tmp_path):
    with pytest.raises(DebtPolicyError, match="not found"):
        load_debt_policy(tmp_path / "absent.json")


def test_an_invalid_policy_file_is_reported_clearly(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    with pytest.raises(DebtPolicyError, match="not valid JSON"):
        load_debt_policy(broken)
