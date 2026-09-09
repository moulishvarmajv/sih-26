"""Entity resolution domain model.

Resolution answers one question: do two *observations* of an entity, seen in
different evidence, denote the same real-world entity? It never rewrites what
was observed. An accepted resolution produces an INFERRED link alongside the
OBSERVED facts, and both stay readable and distinguishable forever.

Four levels, deliberately separate:

    EntityObservation           one entity as one evidence version described it
    EntityResolutionCandidate   a pair worth comparing, and why it was generated
    MatchScore                  what the scorer concluded, and from which signals
    EntityResolutionDecision    the standing outcome for that pair, with lineage

`status` is the workflow state; `recommendation` is what the scorer proposed.
They are kept apart so a human APPROVED decision is never confused with an
automated one, and so a later run cannot quietly overturn a person's judgement.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping


class EntityType(str, Enum):
    PERSON = "PERSON"


class MatchSignal(str, Enum):
    """The comparable facts a decision may be built from. Weights live in policy."""

    EXACT_PHONE = "EXACT_PHONE"
    EXACT_IMEI = "EXACT_IMEI"
    EXACT_ACCOUNT = "EXACT_ACCOUNT"
    EXACT_SOURCE_IDENTIFIER = "EXACT_SOURCE_IDENTIFIER"
    NAME_SIMILARITY = "NAME_SIMILARITY"
    ADDRESS_SIMILARITY = "ADDRESS_SIMILARITY"
    TEMPORAL_CONSISTENCY = "TEMPORAL_CONSISTENCY"
    SOURCE_RELIABILITY = "SOURCE_RELIABILITY"
    CROSS_SOURCE_CONSISTENCY = "CROSS_SOURCE_CONSISTENCY"


class SignalOutcome(str, Enum):
    """What one signal concluded, which is not always literal agreement.

    AGREED: the signal supported the pair. DISAGREED: the signal was applicable
    and did not support it — two different account numbers, or two rows of one
    export where independent corroboration is impossible. NOT_COMPARABLE: there
    was nothing to compare, which lowers the comparable evidence weight rather
    than the score, so a source that never carries an address is not punished
    for it.
    """

    AGREED = "AGREED"
    DISAGREED = "DISAGREED"
    NOT_COMPARABLE = "NOT_COMPARABLE"


class BlockingStrategy(str, Enum):
    """Why a pair was ever compared. Recorded on every candidate."""

    EXACT_PHONE = "EXACT_PHONE"
    EXACT_IMEI = "EXACT_IMEI"
    EXACT_ACCOUNT = "EXACT_ACCOUNT"
    SOURCE_IDENTIFIER = "SOURCE_IDENTIFIER"
    NAME_LOCALITY = "NAME_LOCALITY"


class ConfidenceBand(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Recommendation(str, Enum):
    """What the scorer proposes. Never a statement about a person's conduct."""

    MATCH = "MATCH"
    POSSIBLE_MATCH = "POSSIBLE_MATCH"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    CONFLICT = "CONFLICT"
    UNRESOLVED = "UNRESOLVED"


class ResolutionStatus(str, Enum):
    # Generated and scored, but nothing is asserted: below the review floor.
    CANDIDATE = "CANDIDATE"
    AUTO_ACCEPTED = "AUTO_ACCEPTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class DecidedBy(str, Enum):
    """Automated and human outcomes must stay distinguishable forever."""

    SYSTEM = "SYSTEM"
    HUMAN = "HUMAN"


class ReviewAction(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    DEFER = "DEFER"


class ReasonCode(str, Enum):
    """Machine-stable explanations. Rendered by a client, never parsed as prose."""

    EXACT_PHONE_MATCH = "EXACT_PHONE_MATCH"
    EXACT_IMEI_MATCH = "EXACT_IMEI_MATCH"
    EXACT_ACCOUNT_MATCH = "EXACT_ACCOUNT_MATCH"
    SOURCE_IDENTIFIER_MATCH = "SOURCE_IDENTIFIER_MATCH"
    NAME_SIMILARITY_ABOVE_THRESHOLD = "NAME_SIMILARITY_ABOVE_THRESHOLD"
    ADDRESS_SIMILARITY_ABOVE_THRESHOLD = "ADDRESS_SIMILARITY_ABOVE_THRESHOLD"
    TEMPORAL_CONSISTENT = "TEMPORAL_CONSISTENT"
    CROSS_SOURCE_AGREEMENT = "CROSS_SOURCE_AGREEMENT"
    SCORE_ABOVE_AUTO_ACCEPT = "SCORE_ABOVE_AUTO_ACCEPT"
    SCORE_BELOW_REVIEW_FLOOR = "SCORE_BELOW_REVIEW_FLOOR"
    SCORE_IN_REVIEW_BAND = "SCORE_IN_REVIEW_BAND"
    INSUFFICIENT_EVIDENCE_WEIGHT = "INSUFFICIENT_EVIDENCE_WEIGHT"
    CONFLICT_BLOCKS_AUTO_ACCEPT = "CONFLICT_BLOCKS_AUTO_ACCEPT"
    AMBIGUOUS_ALTERNATIVE = "AMBIGUOUS_ALTERNATIVE"
    PRIOR_HUMAN_REJECTION = "PRIOR_HUMAN_REJECTION"
    SUPERSEDED_BY_NEW_EVIDENCE = "SUPERSEDED_BY_NEW_EVIDENCE"


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def observation_key(entity_type: EntityType, entity_key: str, evidence_version_id: str) -> str:
    """Deterministic id for one entity observation, never random.

    Keyed on the evidence *version*, so re-reading the same version yields the
    same observation and a new version yields a new one.
    """
    return f"OBS-{_digest(entity_type.value, entity_key, evidence_version_id)[:16].upper()}"


def resolution_lineage(case_id: str, entity_type: EntityType, left_key: str, right_key: str) -> str:
    """Stable identity for "this pair of entities, in this case", order-independent."""
    low, high = sorted((left_key, right_key))
    return f"ERL-{_digest(case_id, entity_type.value, low, high)[:16].upper()}"


def candidate_id_for(lineage: str, left_observation: str, right_observation: str) -> str:
    low, high = sorted((left_observation, right_observation))
    return f"ERC-{_digest(lineage, low, high)[:16].upper()}"


def resolution_id_for(lineage: str, version: int) -> str:
    return f"ER-{lineage[4:]}-v{version}"


def entity_ref_id(entity_type: EntityType, entity_key: str) -> str:
    """Opaque, stable id for API responses.

    Hashed for the same reason graph node ids are: returning the raw key would
    hand back the identifier a PARTIAL decision masked.
    """
    return f"{entity_type.value.lower()}:{_digest(entity_type.value, entity_key)[:16]}"


@dataclass(frozen=True)
class EntityObservationRef:
    """The disclosable projection of an observation: identity and provenance only."""

    observation_id: str
    entity_type: EntityType
    entity_key: str
    source_id: str
    evidence_id: str
    evidence_version_id: str
    observed_at: str

    @property
    def entity_ref(self) -> str:
        return entity_ref_id(self.entity_type, self.entity_key)


@dataclass(frozen=True)
class EntityObservation:
    """One entity as a single evidence version described it.

    `attributes` are canonicalised for comparison; `raw_attributes` keep what the
    source actually wrote, so normalization never destroys provenance. Neither is
    ever returned by the API — they are matching material, not disclosure.
    """

    observation_id: str
    case_id: str
    entity_type: EntityType
    entity_key: str
    source_id: str
    evidence_id: str
    evidence_version_id: str
    observed_at: str
    attributes: Mapping[str, str] = field(default_factory=dict)
    raw_attributes: Mapping[str, str] = field(default_factory=dict)

    @property
    def ref(self) -> EntityObservationRef:
        return EntityObservationRef(
            observation_id=self.observation_id,
            entity_type=self.entity_type,
            entity_key=self.entity_key,
            source_id=self.source_id,
            evidence_id=self.evidence_id,
            evidence_version_id=self.evidence_version_id,
            observed_at=self.observed_at,
        )


@dataclass(frozen=True)
class EntityResolutionCandidate:
    """A pair worth comparing. Generating one asserts nothing about identity."""

    candidate_id: str
    case_id: str
    entity_type: EntityType
    lineage_id: str
    left: EntityObservationRef
    right: EntityObservationRef
    blocking_strategy: BlockingStrategy
    blocking_key: str  # the canonical value the pair blocked on, e.g. a phone
    created_at: str


@dataclass(frozen=True)
class MatchEvidence:
    """One signal's contribution. Carries field *names* and numbers, never values."""

    signal: MatchSignal
    attribute: str
    outcome: SignalOutcome
    weight: float
    contribution: float
    similarity: float | None = None


@dataclass(frozen=True)
class ResolutionConflict:
    """A recorded disagreement. Conflicts lower the score and may block auto-accept."""

    attribute: str
    rule: str
    penalty: float
    blocks_auto_accept: bool
    similarity: float | None = None


@dataclass(frozen=True)
class MatchScore:
    """A score that explains itself.

    `score` alone is meaningless without `evidence_weight`: a pair agreeing on
    everything comparable scores 1.0 whether that was one weak attribute or six
    strong ones. The policy's minimum evidence weight is what stops the first
    case from being treated like the second.
    """

    score: float
    evidence_weight: float
    confidence: ConfidenceBand
    confidence_floor: float  # the band's lower bound, so the band is never a bare label
    recommendation: Recommendation
    policy_version: str
    reasons: tuple[ReasonCode, ...] = ()
    evidence: tuple[MatchEvidence, ...] = ()
    conflicts: tuple[ResolutionConflict, ...] = ()

    @property
    def blocks_auto_accept(self) -> bool:
        return any(conflict.blocks_auto_accept for conflict in self.conflicts)


@dataclass(frozen=True)
class ResolutionReview:
    """One human action on a resolution. Append-only: reviews are never edited."""

    review_id: str
    resolution_id: str
    case_id: str
    reviewer_id: str
    action: ReviewAction
    reviewed_at: str
    reason: str | None = None


@dataclass(frozen=True)
class EntityResolutionDecision:
    """The standing outcome for one pair, with the lineage that produced it.

    A decision is never edited in place. A later run that sees different inputs
    supersedes it and records a new version; the superseded record stays
    readable, so the history of what the system believed is preserved.
    """

    resolution_id: str
    lineage_id: str
    resolution_version: int
    case_id: str
    entity_type: EntityType
    candidate_id: str
    left: EntityObservationRef
    right: EntityObservationRef
    status: ResolutionStatus
    score: MatchScore
    policy_version: str
    input_fingerprint: str  # the inputs and policy this decision was computed from
    created_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    decision_actor: DecidedBy | None = None
    decision_reason: str | None = None
    superseded_by: str | None = None

    @property
    def asserts_same_entity(self) -> bool:
        """Only these two states put an INFERRED link into the graph."""
        return self.status in (ResolutionStatus.AUTO_ACCEPTED, ResolutionStatus.APPROVED)

    @property
    def is_open(self) -> bool:
        return self.status is ResolutionStatus.REVIEW_REQUIRED


def with_reasons(
    score: MatchScore, *added: ReasonCode, recommendation: Recommendation | None = None
) -> MatchScore:
    """Copy a score with extra reason codes, and optionally a new proposal.

    Used where an outcome depends on something one pair cannot see — a rival
    candidate scoring almost the same. The original reasons are preserved in
    order, so the record still shows what the pair itself was found to agree on.
    """
    merged = score.reasons + tuple(r for r in added if r not in score.reasons)
    return replace(
        score,
        reasons=merged,
        recommendation=recommendation or score.recommendation,
    )


def input_fingerprint(
    left: EntityObservationRef, right: EntityObservationRef, policy_version: str
) -> str:
    """What a decision was computed from.

    Two runs with the same fingerprint must produce the same decision, which is
    what makes re-running resolution idempotent; a changed fingerprint is what
    makes a new resolution version necessary.
    """
    low, high = sorted((left.observation_id, right.observation_id))
    return _digest(low, high, policy_version)


def explain(score: MatchScore) -> dict[str, Any]:
    """Machine-readable explanation of one score. No prose, no resource values."""
    return {
        "recommendation": score.recommendation.value,
        "score": round(score.score, 4),
        "evidence_weight": round(score.evidence_weight, 4),
        "confidence": score.confidence.value,
        "confidence_floor": score.confidence_floor,
        "policy_version": score.policy_version,
        "reasons": [reason.value for reason in score.reasons],
        "evidence": [
            {
                "signal": item.signal.value,
                "attribute": item.attribute,
                "outcome": item.outcome.value,
                "weight": round(item.weight, 4),
                "contribution": round(item.contribution, 4),
                "similarity": None if item.similarity is None else round(item.similarity, 4),
            }
            for item in score.evidence
        ],
        "conflicts": [
            {
                "attribute": conflict.attribute,
                "rule": conflict.rule,
                "penalty": round(conflict.penalty, 4),
                "blocks_auto_accept": conflict.blocks_auto_accept,
                "similarity": None
                if conflict.similarity is None
                else round(conflict.similarity, 4),
            }
            for conflict in score.conflicts
        ],
    }
