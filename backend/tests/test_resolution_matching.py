"""Normalization, blocking, policy and scoring — the deterministic core.

These tests build observations by hand rather than going through evidence, so a
scoring rule can be pinned down without a database, a case or a reader. The
end-to-end behaviour over the synthetic datasets is covered in
`test_resolution_service.py`.
"""
import pytest

from app.core.normalization import (
    NormalizationError,
    canonical_identifier,
    canonical_phone,
    comparable_name,
    normalized_text,
    similarity,
)
from app.core.resolution.candidates import CandidateGenerator, block_keys
from app.core.resolution.models import (
    BlockingStrategy,
    ConfidenceBand,
    EntityObservation,
    EntityType,
    MatchSignal,
    ReasonCode,
    Recommendation,
    SignalOutcome,
    observation_key,
    resolution_lineage,
)
from app.core.resolution.policy import ResolutionPolicy, ResolutionPolicyError, load_resolution_policy
from app.core.resolution.scoring import DeterministicMatchScorer

AT = "2026-02-01T09:15:00+05:30"


@pytest.fixture
def resolution_policy():
    return load_resolution_policy()


@pytest.fixture
def person_policy(resolution_policy):
    return resolution_policy.for_entity(EntityType.PERSON)


@pytest.fixture
def scorer(resolution_policy):
    return DeterministicMatchScorer(resolution_policy)


def observation(
    entity_key,
    source_id="SYNTHETIC_SUBSCRIBER_REGISTER",
    evidence_id="EV-A",
    version_id="EV-A-v1",
    observed_at=AT,
    **attributes,
):
    return EntityObservation(
        observation_id=observation_key(EntityType.PERSON, entity_key, version_id),
        case_id="CASE-001",
        entity_type=EntityType.PERSON,
        entity_key=entity_key,
        source_id=source_id,
        evidence_id=evidence_id,
        evidence_version_id=version_id,
        observed_at=observed_at,
        attributes=attributes,
        raw_attributes={},
    )


def evidence_for(score, signal):
    return next(item for item in score.evidence if item.signal is signal)


# -- normalization ----------------------------------------------------------


def test_phone_normalization_is_formatting_only():
    assert canonical_phone("+91 98 1234 5678") == "919812345678"
    assert canonical_phone("919812345678") == "919812345678"
    assert canonical_phone("+919812345678") == "919812345678"


def test_normalization_never_invents_a_country_code():
    """A number without a country code stays a different value than one with it."""
    assert canonical_phone("9812345678") != canonical_phone("919812345678")


def test_normalization_is_deterministic_and_idempotent():
    once = canonical_phone("+91 98765 43210")
    assert canonical_phone(once) == once
    assert canonical_identifier("acc-882 13") == canonical_identifier("ACC88213")
    assert comparable_name("  Ananya   SHARMA ") == comparable_name("sharma ananya")
    assert normalized_text("12 M.G. Road,  Pune") == "12 m g road pune"


def test_unusable_values_are_rejected_rather_than_guessed_at():
    with pytest.raises(NormalizationError):
        canonical_phone("not-a-number")
    with pytest.raises(NormalizationError):
        canonical_identifier("   ", "account")


def test_similarity_is_symmetric_and_bounded():
    a, b = comparable_name("Rohan Kulkarni"), comparable_name("Rohit Kulkarni")
    assert similarity(a, b) == similarity(b, a)
    assert 0.0 <= similarity(a, b) <= 1.0
    assert similarity(a, a) == 1.0
    assert similarity("", a) == 0.0


# -- policy -----------------------------------------------------------------


def test_policy_is_data_and_carries_a_version(resolution_policy, person_policy):
    assert resolution_policy.policy_version
    assert person_policy.thresholds.auto_accept > person_policy.thresholds.review_floor
    assert set(person_policy.signals) == set(MatchSignal)


def test_confidence_bands_come_from_policy_not_from_code(person_policy):
    high = person_policy.band_for(0.95)
    low = person_policy.band_for(0.1)
    assert high.band is ConfidenceBand.HIGH
    assert low.band is ConfidenceBand.LOW
    assert high.minimum_score > low.minimum_score


def test_unknown_source_reliability_falls_back_to_the_configured_default(resolution_policy):
    assert resolution_policy.reliability_of("NO-SUCH-SOURCE") == (
        resolution_policy.default_source_reliability
    )
    assert resolution_policy.reliability_of("NO-SUCH-SOURCE") < 1.0


def test_invalid_policy_documents_are_rejected():
    with pytest.raises(ResolutionPolicyError):
        ResolutionPolicy.from_dict({"entity_types": {"PERSON": {}}})
    with pytest.raises(ResolutionPolicyError):
        ResolutionPolicy.from_dict({"policy_version": "v1", "entity_types": {}})


def test_review_floor_above_auto_accept_is_rejected(resolution_policy):
    document = {
        "policy_version": "broken-1",
        "source_reliability": {"default": 0.5},
        "entity_types": {
            "PERSON": {
                "blocking": ["EXACT_PHONE"],
                "signals": {"EXACT_PHONE": {"weight": 1.0, "attribute": "phone"}},
                "thresholds": {
                    "auto_accept": 0.5,
                    "review_floor": 0.9,
                    "ambiguity_margin": 0.05,
                    "minimum_evidence_weight": 0.1,
                },
                "confidence_bands": [{"band": "HIGH", "minimum_score": 0.0}],
            }
        },
    }
    with pytest.raises(ResolutionPolicyError):
        ResolutionPolicy.from_dict(document)


# -- candidate generation ---------------------------------------------------


def test_blocking_keys_are_derived_from_canonical_values():
    left = observation("REG-1", phone="919876543210")
    assert block_keys(BlockingStrategy.EXACT_PHONE, left) == ("919876543210",)
    assert block_keys(BlockingStrategy.EXACT_IMEI, left) == ()


def test_name_blocking_does_not_assume_word_order():
    """Blocking on every name token, so no position is treated as the surname."""
    left = observation("REG-1", name=comparable_name("Rohan Kulkarni"), locality="pune")
    right = observation("REG-2", name=comparable_name("Kulkarni Rohit"), locality="pune")
    shared = set(block_keys(BlockingStrategy.NAME_LOCALITY, left)) & set(
        block_keys(BlockingStrategy.NAME_LOCALITY, right)
    )
    assert shared == {"kulkarni|pune"}


def test_candidates_are_only_generated_within_a_block(person_policy):
    generator = CandidateGenerator(person_policy)
    shared_phone = [
        observation("REG-1", phone="919876543210"),
        observation("REG-2", phone="919876543210"),
        observation("REG-3", phone="919000000000"),
    ]

    candidates = generator.generate(shared_phone, AT)

    # Pair order within a candidate follows the observation ids, not the input
    # order; the lineage the pair belongs to is order-independent either way.
    pairs = {frozenset((c.left.entity_key, c.right.entity_key)) for c in candidates}
    assert pairs == {frozenset(("REG-1", "REG-2"))}
    assert "REG-3" not in {key for pair in pairs for key in pair}


def test_a_candidate_records_why_it_was_generated(person_policy):
    candidates = CandidateGenerator(person_policy).generate(
        [observation("REG-1", phone="919876543210"), observation("REG-2", phone="919876543210")],
        AT,
    )

    candidate = candidates[0]
    assert candidate.blocking_strategy is BlockingStrategy.EXACT_PHONE
    assert candidate.blocking_key == "919876543210"
    assert candidate.lineage_id == resolution_lineage(
        "CASE-001", EntityType.PERSON, "REG-1", "REG-2"
    )


def test_generation_is_deterministic(person_policy):
    generator = CandidateGenerator(person_policy)
    observations = [
        observation("REG-1", phone="919876543210", imei="356938035643809"),
        observation("REG-2", phone="919876543210", imei="356938035643809"),
    ]

    first = generator.generate(observations, AT)
    second = generator.generate(list(reversed(observations)), AT)

    assert [c.candidate_id for c in first] == [c.candidate_id for c in second]
    assert len(first) == 1  # blocking on two keys still yields one candidate


def test_two_observations_of_one_entity_are_not_a_candidate(person_policy):
    """Two sources naming the same key is already one entity, not a resolution."""
    candidates = CandidateGenerator(person_policy).generate(
        [
            observation("SUB-1", source_id="SYNTHETIC_CDR", version_id="EV-A-v1", phone="91987"),
            observation("SUB-1", version_id="EV-B-v1", phone="91987"),
        ],
        AT,
    )

    assert candidates == []


def test_generating_a_candidate_asserts_nothing(person_policy):
    candidate = CandidateGenerator(person_policy).generate(
        [observation("REG-1", phone="919876543210"), observation("REG-2", phone="919876543210")],
        AT,
    )[0]

    assert not hasattr(candidate, "status")
    assert not hasattr(candidate, "score")


# -- scoring ----------------------------------------------------------------


def test_exact_identifier_agreement_is_recorded_as_a_signal(scorer):
    score = scorer.score(
        observation("REG-1", phone="919876543210"),
        observation("REG-2", phone="919876543210"),
    )

    phone = evidence_for(score, MatchSignal.EXACT_PHONE)
    assert phone.outcome is SignalOutcome.AGREED
    assert phone.contribution == phone.weight
    assert ReasonCode.EXACT_PHONE_MATCH in score.reasons


def test_formatting_variation_alone_resolves_deterministically(scorer):
    """`+91 98765 43210` and `919876543210` are one identifier written two ways."""
    left = observation("REG-1", phone=canonical_phone("+91 98765 43210"))
    right = observation("REG-2", phone=canonical_phone("919876543210"))

    assert evidence_for(scorer.score(left, right), MatchSignal.EXACT_PHONE).outcome is (
        SignalOutcome.AGREED
    )


def test_a_missing_attribute_is_not_comparable_rather_than_a_disagreement(scorer):
    score = scorer.score(
        observation("REG-1", phone="919876543210", name="ananya sharma"),
        observation("REG-2", phone="919876543210"),
    )

    name = evidence_for(score, MatchSignal.NAME_SIMILARITY)
    assert name.outcome is SignalOutcome.NOT_COMPARABLE
    assert name.contribution == 0.0
    assert name.weight > 0.0  # the weight is still reported, so the gap is visible


def test_evidence_weight_reports_how_much_was_comparable(scorer):
    thin = scorer.score(
        observation("REG-1", phone="919876543210"),
        observation("REG-2", phone="919876543210"),
    )
    rich = scorer.score(
        observation("REG-1", phone="919876543210", imei="356938035643809", name="a b"),
        observation("REG-2", phone="919876543210", imei="356938035643809", name="a b"),
    )

    assert rich.evidence_weight > thin.evidence_weight
    assert thin.score > 0.9  # agreeing on everything comparable is still a high score


def test_multi_signal_agreement_scores_as_a_match(scorer):
    score = scorer.score(
        observation(
            "SUB-SYNTH-0001",
            source_id="SYNTHETIC_CDR",
            evidence_id="EV-CDR",
            version_id="EV-CDR-v1",
            phone="919876543210",
            imei="356938035643809",
            observed_from="2026-02-01T09:15:00+05:30",
            observed_to="2026-02-02T08:03:00+05:30",
        ),
        observation(
            "REG-1001",
            phone="919876543210",
            imei="356938035643809",
            source_entity_ref="SUBSYNTH0001",
            observed_from="2026-01-15T00:00:00+05:30",
            observed_to="2026-01-15T00:00:00+05:30",
        ),
    )

    assert score.recommendation is Recommendation.MATCH
    assert score.confidence is ConfidenceBand.HIGH
    assert score.score >= score.confidence_floor
    assert {
        ReasonCode.EXACT_PHONE_MATCH,
        ReasonCode.EXACT_IMEI_MATCH,
        ReasonCode.SOURCE_IDENTIFIER_MATCH,
        ReasonCode.CROSS_SOURCE_AGREEMENT,
    } <= set(score.reasons)


def test_confidence_is_explained_by_the_band_it_came_from(scorer, person_policy):
    score = scorer.score(
        observation("REG-1", phone="919876543210"),
        observation("REG-2", phone="919876543210"),
    )

    assert score.score >= score.confidence_floor
    assert score.confidence_floor == person_policy.band_for(score.score).minimum_score


def test_agreement_on_too_little_does_not_recommend_a_match(scorer, person_policy):
    """A high score over a thin comparison is a possible match, never a match."""
    score = scorer.score(
        observation("REG-1", account_number="ACC88213"),
        observation("REG-2", account_number="ACC88213"),
    )

    assert score.score >= person_policy.thresholds.auto_accept
    assert score.evidence_weight < person_policy.thresholds.minimum_evidence_weight
    assert score.recommendation is Recommendation.POSSIBLE_MATCH
    assert ReasonCode.INSUFFICIENT_EVIDENCE_WEIGHT in score.reasons


def test_a_conflicting_identity_reference_blocks_a_match(scorer):
    score = scorer.score(
        observation("REG-1", phone="919876543210", imei="35693", national_id_ref="NIDA"),
        observation("REG-2", phone="919876543210", imei="35693", national_id_ref="NIDB"),
    )

    assert score.recommendation is Recommendation.CONFLICT
    assert score.blocks_auto_accept
    assert "national_id_ref" in {conflict.attribute for conflict in score.conflicts}
    assert ReasonCode.CONFLICT_BLOCKS_AUTO_ACCEPT in score.reasons


def test_a_conflict_is_surfaced_rather_than_scored_away(scorer, person_policy):
    """The penalty stops an automatic merge; it must not hide the pair."""
    score = scorer.score(
        observation("REG-1", phone="919876543210", imei="35693", national_id_ref="NIDA"),
        observation("REG-2", phone="919876543210", imei="35693", national_id_ref="NIDB"),
    )

    assert score.score < person_policy.thresholds.review_floor
    assert score.recommendation is not Recommendation.UNRESOLVED


def test_similar_names_alone_do_not_make_a_match(scorer):
    score = scorer.score(
        observation(
            "REG-2003",
            phone="919845777001",
            name=comparable_name("Rohan Kulkarni"),
            address="8 baner pune road",
            account_number="ACC50110",
            locality="pune",
        ),
        observation(
            "REG-2004",
            phone="919845777002",
            name=comparable_name("Rohit Kulkarni"),
            address="91 kothrud lane pune",
            account_number="ACC50994",
            locality="pune",
        ),
    )

    assert score.recommendation is Recommendation.UNRESOLVED
    assert ReasonCode.SCORE_BELOW_REVIEW_FLOOR in score.reasons


def test_scoring_is_deterministic_and_order_independent(scorer):
    left = observation("REG-1", phone="919876543210", name="ananya sharma")
    right = observation("REG-2", phone="919876543210", name="ananya sharma")

    first = scorer.score(left, right)
    second = scorer.score(left, right)
    reversed_order = scorer.score(right, left)

    assert first == second
    assert first.score == reversed_order.score
    assert first.recommendation is reversed_order.recommendation


def test_temporal_distance_beyond_the_policy_gap_is_a_conflict(scorer):
    score = scorer.score(
        observation(
            "REG-1",
            phone="919876543210",
            observed_from="2019-01-01T00:00:00+00:00",
            observed_to="2019-02-01T00:00:00+00:00",
        ),
        observation(
            "REG-2",
            phone="919876543210",
            observed_from="2026-01-01T00:00:00+00:00",
            observed_to="2026-02-01T00:00:00+00:00",
        ),
    )

    assert evidence_for(score, MatchSignal.TEMPORAL_CONSISTENCY).outcome is (
        SignalOutcome.DISAGREED
    )
    assert "observed_at" in {conflict.attribute for conflict in score.conflicts}


def test_one_source_repeating_itself_is_not_corroboration(scorer):
    score = scorer.score(
        observation("REG-1", evidence_id="EV-A", phone="919876543210"),
        observation("REG-2", evidence_id="EV-A", phone="919876543210"),
    )

    assert evidence_for(score, MatchSignal.CROSS_SOURCE_CONSISTENCY).outcome is (
        SignalOutcome.DISAGREED
    )
    assert ReasonCode.CROSS_SOURCE_AGREEMENT not in score.reasons


def test_explanations_never_carry_the_values_that_were_compared(scorer):
    from app.core.resolution.models import explain

    payload = explain(
        scorer.score(
            observation("REG-1", phone="919876543210", national_id_ref="NIDA"),
            observation("REG-2", phone="919876543210", national_id_ref="NIDB"),
        )
    )

    assert "919876543210" not in str(payload)
    assert "NIDA" not in str(payload)
    assert {item["attribute"] for item in payload["evidence"]} >= {"phone", "imei"}


def test_no_outcome_vocabulary_describes_conduct(scorer):
    """Resolution reports identity, never criminality."""
    forbidden = {"guilty", "criminal", "suspect", "kingpin", "offender", "accused"}
    vocabulary = {value.lower() for value in Recommendation.__members__}
    vocabulary |= {value.lower() for value in ReasonCode.__members__}

    assert not any(word in term for term in vocabulary for word in forbidden)
