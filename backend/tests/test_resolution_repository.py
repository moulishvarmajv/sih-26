"""Persistence rules the resolution repository owns.

The transitions tested here are the ones no caller should have to remember:
saving a decision supersedes the previous live one for its lineage, only an open
decision can be closed, and nothing is ever deleted or rewritten.
"""
import pytest

from app.core.resolution.models import (
    BlockingStrategy,
    ConfidenceBand,
    DecidedBy,
    EntityObservationRef,
    EntityResolutionCandidate,
    EntityResolutionDecision,
    EntityType,
    MatchEvidence,
    MatchScore,
    MatchSignal,
    ReasonCode,
    Recommendation,
    ResolutionConflict,
    ResolutionReview,
    ResolutionStatus,
    ReviewAction,
    SignalOutcome,
    candidate_id_for,
    input_fingerprint,
    observation_key,
    resolution_id_for,
    resolution_lineage,
)
from app.core.resolution.repository import ResolutionRepositoryError
from app.infrastructure.sqlite_resolution_repository import SQLiteResolutionRepository

CASE = "CASE-001"
POLICY = "resolution-1.0.0"


@pytest.fixture
def repository(tmp_path):
    store = SQLiteResolutionRepository(tmp_path / "resolutions.db")
    yield store
    store.close()


def ref(entity_key, evidence_id="EV-A", version_id="EV-A-v1"):
    return EntityObservationRef(
        observation_id=observation_key(EntityType.PERSON, entity_key, version_id),
        entity_type=EntityType.PERSON,
        entity_key=entity_key,
        source_id="SYNTHETIC_SUBSCRIBER_REGISTER",
        evidence_id=evidence_id,
        evidence_version_id=version_id,
        observed_at="2026-02-01T00:00:00+00:00",
    )


def score(value=0.9):
    return MatchScore(
        score=value,
        evidence_weight=0.7,
        confidence=ConfidenceBand.HIGH,
        confidence_floor=0.8,
        recommendation=Recommendation.MATCH,
        policy_version=POLICY,
        reasons=(ReasonCode.EXACT_PHONE_MATCH,),
        evidence=(
            MatchEvidence(
                signal=MatchSignal.EXACT_PHONE,
                attribute="phone",
                outcome=SignalOutcome.AGREED,
                weight=0.3,
                contribution=0.3,
            ),
            MatchEvidence(
                signal=MatchSignal.NAME_SIMILARITY,
                attribute="name",
                outcome=SignalOutcome.DISAGREED,
                weight=0.1,
                contribution=0.0,
                similarity=0.42,
            ),
        ),
        conflicts=(
            ResolutionConflict(
                attribute="account_number",
                rule="DIFFERENT_ACCOUNT_NUMBER",
                penalty=0.15,
                blocks_auto_accept=False,
            ),
        ),
    )


def decision(version=1, status=ResolutionStatus.REVIEW_REQUIRED, version_id="EV-A-v1"):
    left, right = ref("REG-1", version_id=version_id), ref("REG-2", version_id=version_id)
    lineage = resolution_lineage(CASE, EntityType.PERSON, left.entity_key, right.entity_key)
    return EntityResolutionDecision(
        resolution_id=resolution_id_for(lineage, version),
        lineage_id=lineage,
        resolution_version=version,
        case_id=CASE,
        entity_type=EntityType.PERSON,
        candidate_id=candidate_id_for(lineage, left.observation_id, right.observation_id),
        left=left,
        right=right,
        status=status,
        score=score(),
        policy_version=POLICY,
        input_fingerprint=input_fingerprint(left, right, POLICY),
        created_at="2026-02-02T00:00:00+00:00",
    )


def test_a_decision_round_trips_with_its_full_explanation(repository):
    stored = repository.save_decision(decision())

    read_back = repository.get_decision(stored.resolution_id)

    assert read_back == stored
    assert read_back.score.reasons == (ReasonCode.EXACT_PHONE_MATCH,)
    assert read_back.score.evidence[1].similarity == 0.42
    assert read_back.score.conflicts[0].rule == "DIFFERENT_ACCOUNT_NUMBER"


def test_a_score_is_never_stored_as_a_bare_number(repository):
    """Read back years later, a decision still says which signals produced it."""
    stored = repository.save_decision(decision())

    read_back = repository.get_decision(stored.resolution_id)

    assert read_back.score.evidence
    assert read_back.score.policy_version == POLICY
    assert read_back.score.confidence_floor == 0.8


def test_saving_a_new_version_supersedes_the_previous_one(repository):
    first = repository.save_decision(decision(version=1))

    second = repository.save_decision(decision(version=2, version_id="EV-A-v2"))

    superseded = repository.get_decision(first.resolution_id)
    assert superseded.status is ResolutionStatus.SUPERSEDED
    assert superseded.superseded_by == second.resolution_id
    assert repository.get_live_decision(first.lineage_id).resolution_id == second.resolution_id


def test_history_survives_supersession(repository):
    first = repository.save_decision(decision(version=1))
    repository.save_decision(decision(version=2, version_id="EV-A-v2"))

    lineage = repository.list_lineage(first.lineage_id)

    assert [entry.resolution_version for entry in lineage] == [1, 2]
    assert lineage[0].score.score == 0.9  # the old score is still readable


def test_only_an_open_decision_can_be_closed(repository):
    auto = repository.save_decision(decision(status=ResolutionStatus.AUTO_ACCEPTED))

    with pytest.raises(ResolutionRepositoryError):
        repository.update_status(
            auto.resolution_id,
            ResolutionStatus.APPROVED,
            "2026-02-03T00:00:00+00:00",
            "USR-1",
            DecidedBy.HUMAN.value,
        )


def test_closing_a_decision_records_who_decided_and_when(repository):
    open_decision = repository.save_decision(decision())

    updated = repository.update_status(
        open_decision.resolution_id,
        ResolutionStatus.APPROVED,
        "2026-02-03T00:00:00+00:00",
        "USR-1",
        DecidedBy.HUMAN.value,
        decision_reason="confirmed",
    )

    assert updated.status is ResolutionStatus.APPROVED
    assert updated.decision_actor is DecidedBy.HUMAN
    assert updated.decided_by == "USR-1"
    assert updated.decision_reason == "confirmed"


def test_a_closed_decision_cannot_be_reopened(repository):
    open_decision = repository.save_decision(decision())
    repository.update_status(
        open_decision.resolution_id,
        ResolutionStatus.REJECTED,
        "2026-02-03T00:00:00+00:00",
        "USR-1",
        DecidedBy.HUMAN.value,
    )

    with pytest.raises(ResolutionRepositoryError):
        repository.update_status(
            open_decision.resolution_id,
            ResolutionStatus.APPROVED,
            "2026-02-04T00:00:00+00:00",
            "USR-2",
            DecidedBy.HUMAN.value,
        )


def test_reviews_are_append_only(repository):
    stored = repository.save_decision(decision())
    for index, action in enumerate((ReviewAction.DEFER, ReviewAction.APPROVE), start=1):
        repository.add_review(
            ResolutionReview(
                review_id=f"REV-{index}",
                resolution_id=stored.resolution_id,
                case_id=CASE,
                reviewer_id="USR-1",
                action=action,
                reviewed_at=f"2026-02-0{index}T00:00:00+00:00",
            )
        )

    reviews = repository.list_reviews(stored.resolution_id)

    assert [review.action for review in reviews] == [
        ReviewAction.DEFER,
        ReviewAction.APPROVE,
    ]
    with pytest.raises(ResolutionRepositoryError):
        repository.add_review(reviews[0])


def test_decisions_are_scoped_to_their_case(repository):
    repository.save_decision(decision())

    assert repository.list_decisions(CASE)
    assert repository.list_decisions("CASE-OTHER") == []


def test_decisions_can_be_filtered_by_status(repository):
    repository.save_decision(decision())

    assert repository.list_decisions(CASE, (ResolutionStatus.REVIEW_REQUIRED,))
    assert repository.list_decisions(CASE, (ResolutionStatus.APPROVED,)) == []


def test_saving_the_same_candidate_twice_is_a_no_op(repository):
    left, right = ref("REG-1"), ref("REG-2")
    lineage = resolution_lineage(CASE, EntityType.PERSON, "REG-1", "REG-2")
    candidate = EntityResolutionCandidate(
        candidate_id=candidate_id_for(lineage, left.observation_id, right.observation_id),
        case_id=CASE,
        entity_type=EntityType.PERSON,
        lineage_id=lineage,
        left=left,
        right=right,
        blocking_strategy=BlockingStrategy.EXACT_PHONE,
        blocking_key="919876543210",
        created_at="2026-02-01T00:00:00+00:00",
    )

    repository.save_candidate(candidate)
    repository.save_candidate(candidate)

    assert repository.list_candidates(CASE) == [candidate]


def test_a_duplicate_resolution_id_is_rejected(repository):
    repository.save_decision(decision())

    with pytest.raises(ResolutionRepositoryError):
        repository.save_decision(decision())
