"""Debt detection, over views built by hand so every answer is known in advance.

The detectors are pure, so these tests need no database, no clock and no
authorization: one fact is wrong in the view, and exactly one item comes out.
The negative cases matter as much as the positive ones — a metric that reports a
gap wherever it looks is not measuring anything.
"""
import pytest

from app.core.debt import detectors
from app.core.debt.models import DebtCategory, DebtReason, DebtSeverity
from app.core.debt.policy import load_debt_policy
from tests.debt_builders import (
    REGISTER,
    SUMMARY,
    analysed,
    conflict,
    evidence,
    result,
    resolution,
    signal,
    view,
)


@pytest.fixture
def policy():
    return load_debt_policy()


def categories(findings):
    return [finding.category for finding in findings]


def reasons(findings):
    return [finding.reason for finding in findings]


def of(findings, category):
    return [finding for finding in findings if finding.category is category]


# -- unresolved identity -----------------------------------------------------


def test_a_pair_that_reached_no_conclusion_is_unresolved_debt(policy):
    found = detectors.unresolved(
        view(resolutions=(resolution(status="CANDIDATE", recommendation="UNRESOLVED"),)),
        policy,
    )

    assert len(found) == 1
    assert found[0].category is DebtCategory.UNRESOLVED
    assert found[0].reason is DebtReason.RESOLUTION_BELOW_REVIEW_FLOOR
    assert found[0].supporting_evidence_ids == ("EV-1", "EV-2")


@pytest.mark.parametrize("status", ["AUTO_ACCEPTED", "APPROVED", "REJECTED"])
def test_a_settled_pair_creates_no_unresolved_debt(policy, status):
    assert detectors.unresolved(view(resolutions=(resolution(status=status),)), policy) == []


def test_unresolved_debt_names_the_pair_without_asserting_they_match(policy):
    found = detectors.unresolved(
        view(resolutions=(resolution(status="CANDIDATE", recommendation="UNRESOLVED"),)), policy
    )

    explanation = found[0].explanation
    assert explanation["recommendation"] == "UNRESOLVED"
    assert "SAME" not in str(explanation).upper()


# -- human review ------------------------------------------------------------


def test_a_decision_waiting_on_a_person_is_human_review_debt(policy):
    found = detectors.human_review(
        view(resolutions=(resolution(status="REVIEW_REQUIRED"),)), policy
    )

    assert reasons(found) == [DebtReason.RESOLUTION_AWAITING_REVIEW]
    assert found[0].severity is policy.resolution.awaiting_review_severity
    assert found[0].blocking_reason.value == "AWAITING_HUMAN_REVIEW"


def test_a_deferred_review_stays_open_with_its_own_reason(policy):
    found = detectors.human_review(
        view(resolutions=(resolution(status="REVIEW_REQUIRED", review_actions=("DEFER",)),)),
        policy,
    )

    assert reasons(found) == [DebtReason.RESOLUTION_REVIEW_DEFERRED]
    assert found[0].explanation["review_count"] == 1


@pytest.mark.parametrize("status", ["APPROVED", "REJECTED"])
def test_a_completed_review_removes_the_human_review_debt(policy, status):
    decided = view(resolutions=(resolution(status=status, review_actions=("APPROVE",)),))

    assert detectors.human_review(decided, policy) == []


def test_one_open_decision_produces_exactly_one_item(policy):
    """Not two: an open pair is one gap, however many ways it can be described."""
    found = detectors.detect(
        view(
            evidence_items=(analysed("EV-1"), analysed("EV-2", source_id=REGISTER)),
            resolutions=(resolution(status="REVIEW_REQUIRED"),),
        ),
        policy,
    )

    about_the_pair = [
        finding
        for finding in found
        if finding.category in (DebtCategory.UNRESOLVED, DebtCategory.HUMAN_REVIEW)
    ]
    assert len(about_the_pair) == 1


# -- conflicting evidence ----------------------------------------------------


def test_a_recorded_conflict_becomes_conflict_debt(policy):
    found = detectors.conflicting(
        view(resolutions=(resolution(status="REVIEW_REQUIRED", conflicts=(conflict(),)),)),
        policy,
    )

    assert reasons(found) == [DebtReason.RESOLUTION_CONFLICT_BLOCKS_ACCEPTANCE]
    assert found[0].explanation["conflict_rule"] == "DIFFERENT_NATIONAL_ID_REFERENCE"
    assert found[0].explanation["conflict_attribute"] == "national_id_ref"
    assert found[0].explanation["participating_evidence_ids"] == ["EV-1", "EV-2"]


def test_a_non_blocking_conflict_weighs_less_than_a_blocking_one(policy):
    blocking = detectors.conflicting(
        view(resolutions=(resolution(status="REVIEW_REQUIRED", conflicts=(conflict(),)),)),
        policy,
    )[0]
    minor = detectors.conflicting(
        view(
            resolutions=(
                resolution(
                    status="REVIEW_REQUIRED",
                    conflicts=(conflict(rule="DIFFERENT_ACCOUNT_NUMBER", blocks=False),),
                ),
            )
        ),
        policy,
    )[0]

    assert blocking.severity is DebtSeverity.HIGH
    assert minor.severity is DebtSeverity.MEDIUM
    assert minor.reason is DebtReason.RESOLUTION_ATTRIBUTE_CONFLICT


def test_a_rejected_pair_is_not_a_conflict(policy):
    """A person concluded they are different entities. The disagreement was right."""
    rejected = view(resolutions=(resolution(status="REJECTED", conflicts=(conflict(),)),))

    assert detectors.conflicting(rejected, policy) == []


def test_a_disagreement_inside_one_export_is_reported_from_its_analysis(policy):
    disagreeing = evidence(
        "EV-1",
        results=(
            result(
                "RES-EV-1",
                version_id="EV-1-v1",
                conflict_metrics={"imei_with_multiple_imsi_count": 2},
            ),
        ),
    )

    found = detectors.conflicting(view(evidence_items=(disagreeing,)), policy)

    assert reasons(found) == [DebtReason.OBSERVATIONS_DISAGREE_WITHIN_EVIDENCE]
    assert found[0].explanation["conflict_count"] == 2
    assert found[0].explanation["conflict_metric"] == "imei_with_multiple_imsi_count"


def test_no_conflict_is_invented_where_the_metric_is_zero(policy):
    agreeing = evidence(
        "EV-1",
        results=(result("RES-1", conflict_metrics={"imei_with_multiple_imsi_count": 0}),),
    )

    assert detectors.conflicting(view(evidence_items=(agreeing,)), policy) == []


# -- weak / low-trust support ------------------------------------------------


def test_low_trust_evidence_that_holds_a_finding_up_is_debt(policy):
    inferred = analysed("EV-9", classification="INFERRED")

    found = detectors.weak(
        view(evidence_items=(inferred,), signals=(signal(supporting_evidence_ids=("EV-9",)),)),
        policy,
    )

    assert reasons(found) == [DebtReason.SUPPORTING_EVIDENCE_BELOW_TRUST_FLOOR]
    assert found[0].explanation["classification"] == "INFERRED"
    assert found[0].explanation["materially_supports_reasoning"] is True


def test_low_trust_evidence_nothing_depends_on_is_not_debt(policy):
    """An INFERRED fact is not automatically bad evidence."""
    inferred = analysed("EV-9", classification="INFERRED")

    assert detectors.weak(view(evidence_items=(inferred,)), policy) == []


def test_observed_evidence_is_never_weak_debt(policy):
    observed = analysed("EV-1")

    assert (
        detectors.weak(
            view(evidence_items=(observed,), signals=(signal(),)), policy
        )
        == []
    )


def test_an_accepted_identity_link_also_counts_as_reliance(policy):
    inferred = analysed("EV-9", classification="INFERRED")
    accepted = resolution(status="AUTO_ACCEPTED", left_evidence_id="EV-9", right_evidence_id="EV-1")

    found = detectors.weak(view(evidence_items=(inferred,), resolutions=(accepted,)), policy)

    assert len(found) == 1


# -- missing expected evidence -----------------------------------------------


def test_an_expected_source_that_is_absent_is_missing_debt(policy):
    found = detectors.missing(view(evidence_items=(analysed("EV-1"),)), policy)

    absent = [
        finding
        for finding in found
        if finding.explanation.get("expectation_id") == "EXPECT_SUBSCRIBER_REGISTER"
    ]
    assert len(absent) == 1
    assert absent[0].reason is DebtReason.EXPECTED_SOURCE_ABSENT
    assert absent[0].explanation["expected_source_id"] == "SYNTHETIC_SUBSCRIBER_REGISTER"


def test_an_expected_source_that_is_present_creates_nothing(policy):
    both = view(evidence_items=(analysed("EV-1"), analysed("EV-2", source_id=REGISTER)))

    found = detectors.missing(both, policy)

    assert all(
        finding.explanation.get("expectation_id") != "EXPECT_SUBSCRIBER_REGISTER"
        for finding in found
    )


def test_an_expectation_does_not_fire_without_its_trigger(policy):
    """A case with no CDR evidence is not missing a subscriber register."""
    register_only = view(evidence_items=(analysed("EV-2", source_id=REGISTER),))

    assert detectors.missing(register_only, policy) == []


def test_evidence_with_no_current_analysis_is_missing_debt(policy):
    found = detectors.missing(view(evidence_items=(evidence("EV-1"),)), policy)

    analysis = [
        finding for finding in found if finding.reason is DebtReason.EXPECTED_ANALYSIS_ABSENT
    ]
    assert len(analysis) == 1
    assert analysis[0].subject.reference == "EV-1"
    assert analysis[0].explanation["expected_task_type"] == SUMMARY


def test_a_stale_analysis_is_not_reported_as_a_missing_one(policy):
    """One gap, one category: it is out of date, not absent."""
    superseded = evidence(
        "EV-1",
        version_count=2,
        results=(result("RES-1", state="STALE", version_id="EV-1-v1"),),
    )

    found = detectors.missing(view(evidence_items=(superseded,)), policy)

    assert all(finding.reason is not DebtReason.EXPECTED_ANALYSIS_ABSENT for finding in found)


# -- stale analysis ----------------------------------------------------------


def test_a_result_from_a_superseded_version_is_stale_debt(policy):
    superseded = evidence(
        "EV-1",
        version_count=2,
        results=(result("RES-1", state="STALE", version_id="EV-1-v1"),),
    )

    found = detectors.stale(view(evidence_items=(superseded,)), policy)

    assert reasons(found) == [DebtReason.RESULT_COMPUTED_FROM_SUPERSEDED_VERSION]
    assert found[0].explanation["stale_result_ids"] == ["RES-1"]
    assert found[0].explanation["latest_version_id"] == "EV-1-v2"


def test_recomputing_against_the_current_version_clears_stale_debt(policy):
    recomputed = evidence(
        "EV-1",
        version_count=2,
        results=(
            result("RES-1", state="STALE", version_id="EV-1-v1"),
            result("RES-2", state="CURRENT", version_id="EV-1-v2"),
        ),
    )

    assert detectors.stale(view(evidence_items=(recomputed,)), policy) == []


def test_a_superseded_result_is_history_not_staleness(policy):
    """A newer result replacing an older one is healthy, not a gap."""
    replaced = evidence(
        "EV-1",
        results=(
            result("RES-1", state="SUPERSEDED", version_id="EV-1-v1"),
            result("RES-2", state="CURRENT", version_id="EV-1-v1"),
        ),
    )

    assert detectors.stale(view(evidence_items=(replaced,)), policy) == []


# -- finding support ---------------------------------------------------------


def test_a_finding_on_clean_evidence_creates_no_debt(policy):
    clean = view(
        evidence_items=(analysed("EV-1"), analysed("EV-2", source_id=REGISTER)),
        signals=(signal(supporting_evidence_ids=("EV-1",)),),
    )

    found = detectors.detect(clean, policy)

    assert of(found, DebtCategory.UNSUPPORTED_FINDING) == []


def test_a_finding_resting_on_an_unresolved_pair_names_the_dependency(policy):
    depending = view(
        evidence_items=(analysed("EV-1"), analysed("EV-2", source_id=REGISTER)),
        resolutions=(resolution(status="REVIEW_REQUIRED"),),
        signals=(signal(supporting_evidence_ids=("EV-1",)),),
    )

    found = of(detectors.detect(depending, policy), DebtCategory.UNSUPPORTED_FINDING)

    assert reasons(found) == [DebtReason.FINDING_DEPENDS_ON_UNRESOLVED_ENTITY]
    assert found[0].related_finding_ids == ("SIG-1",)
    assert found[0].explanation["affected_evidence_ids"] == ["EV-1"]


def test_a_finding_resting_on_weak_evidence_names_the_dependency(policy):
    depending = view(
        evidence_items=(
            analysed("EV-9", classification="INFERRED"),
            analysed("EV-2", source_id=REGISTER),
        ),
        signals=(signal(supporting_evidence_ids=("EV-9",)),),
    )

    found = of(detectors.detect(depending, policy), DebtCategory.UNSUPPORTED_FINDING)

    assert reasons(found) == [DebtReason.FINDING_DEPENDS_ON_WEAK_EVIDENCE]


def test_a_finding_with_no_supporting_evidence_at_all_is_debt(policy):
    unsupported = view(
        evidence_items=(analysed("EV-1"), analysed("EV-2", source_id=REGISTER)),
        signals=(signal(supporting_evidence_ids=()),),
    )

    found = of(detectors.detect(unsupported, policy), DebtCategory.UNSUPPORTED_FINDING)

    assert reasons(found) == [DebtReason.FINDING_HAS_NO_SUPPORTING_EVIDENCE]
    assert found[0].severity is policy.finding_support.no_support_severity


def test_a_findings_own_thin_connection_caveat_is_carried_through(policy):
    thin = view(
        evidence_items=(analysed("EV-1"), analysed("EV-2", source_id=REGISTER)),
        signals=(
            signal(
                signal_type="CROSS_DOMAIN_BRIDGE",
                reasons=("REMOVAL_SEPARATES_GRAPH", "RESTS_ON_SINGLE_WEAK_RELATIONSHIP"),
            ),
        ),
    )

    found = of(detectors.detect(thin, policy), DebtCategory.UNSUPPORTED_FINDING)

    assert reasons(found) == [DebtReason.FINDING_RESTS_ON_SINGLE_WEAK_RELATIONSHIP]


# -- determinism and shape ---------------------------------------------------


def test_detection_is_deterministic(policy):
    populated = view(
        evidence_items=(
            evidence("EV-1"),
            analysed("EV-9", classification="INFERRED"),
            analysed("EV-2", source_id=REGISTER),
        ),
        resolutions=(
            resolution("ERL-A", status="REVIEW_REQUIRED", conflicts=(conflict(),)),
            resolution("ERL-B", status="CANDIDATE", recommendation="UNRESOLVED"),
        ),
        signals=(signal(supporting_evidence_ids=("EV-1", "EV-9")),),
    )

    first = detectors.detect(populated, policy)
    second = detectors.detect(populated, policy)

    assert [(f.category, f.reason, f.subject.reference, f.discriminators) for f in first] == [
        (f.category, f.reason, f.subject.reference, f.discriminators) for f in second
    ]


def test_an_empty_case_has_no_debt(policy):
    assert detectors.detect(view(), policy) == []


def test_no_detector_reports_a_resource_value(policy):
    """Explanations name attributes, rules and ids — never what they contained."""
    populated = view(
        evidence_items=(
            evidence("EV-1"),
            analysed("EV-9", classification="INFERRED"),
        ),
        resolutions=(resolution("ERL-A", status="REVIEW_REQUIRED", conflicts=(conflict(),)),),
        signals=(signal(supporting_evidence_ids=("EV-1", "EV-9")),),
    )

    rendered = str([finding.explanation for finding in detectors.detect(populated, policy)])

    for value in ("+91", "919840", "Menon", "NID-SYNTH", "35988103"):
        assert value not in rendered


def test_the_per_category_cap_is_applied(policy):
    from dataclasses import replace

    capped = replace(policy, limits=replace(policy.limits, max_items_per_category=2))
    many = view(
        resolutions=tuple(
            resolution(f"ERL-{index}", status="REVIEW_REQUIRED") for index in range(5)
        )
    )

    found = of(detectors.detect(many, capped), DebtCategory.HUMAN_REVIEW)

    assert len(found) == 2
