"""Deterministic match scoring.

Pure: a function of (policy, two observations). No storage, no clock, no
randomness, no model — the same pair and the same policy version always produce
the same score, the same reasons and the same recommendation. That is what makes
a resolution explainable months later.

The scoring model, in full:

    score = (sum of earned contributions - sum of conflict penalties)
            / (sum of weights of the signals that were *comparable*)

Two numbers come out, and both matter:

- `score` is how well the pair agreed on what could be compared.
- `evidence_weight` is how much could be compared at all.

Dividing by the comparable weight rather than by the total means a source that
simply does not carry an address is not punished for it. Reporting the
comparable weight separately means a pair agreeing on one weak attribute cannot
masquerade as a pair agreeing on six strong ones: the policy's minimum evidence
weight is checked before anything is auto-accepted.

Conflicts are disagreements the policy names explicitly. They subtract, and some
of them block auto-acceptance outright however high the score — a shared phone
number with two different national identity references is a question for a
person, not a merge.
"""
from __future__ import annotations

from app.core.normalization import similarity as text_similarity
from app.core.resolution.extraction import (
    ATTR_ACCOUNT,
    ATTR_ADDRESS,
    ATTR_IMEI,
    ATTR_NAME,
    ATTR_PHONE,
    ATTR_SOURCE_ENTITY_REF,
)
from app.core.resolution.candidates import canonical_entity_key
from app.core.resolution.models import (
    EntityObservation,
    MatchEvidence,
    MatchScore,
    MatchSignal,
    ReasonCode,
    Recommendation,
    ResolutionConflict,
    SignalOutcome,
)
from app.core.resolution.policy import EntityTypePolicy, ResolutionPolicy, SignalRule
from app.infrastructure.clock import parse_iso

_SECONDS_PER_DAY = 86400.0

#: Which reason code an exact-identifier signal contributes when it agrees.
_EXACT_REASONS = {
    MatchSignal.EXACT_PHONE: ReasonCode.EXACT_PHONE_MATCH,
    MatchSignal.EXACT_IMEI: ReasonCode.EXACT_IMEI_MATCH,
    MatchSignal.EXACT_ACCOUNT: ReasonCode.EXACT_ACCOUNT_MATCH,
    MatchSignal.EXACT_SOURCE_IDENTIFIER: ReasonCode.SOURCE_IDENTIFIER_MATCH,
}

_EXACT_ATTRIBUTES = {
    MatchSignal.EXACT_PHONE: ATTR_PHONE,
    MatchSignal.EXACT_IMEI: ATTR_IMEI,
    MatchSignal.EXACT_ACCOUNT: ATTR_ACCOUNT,
}


class DeterministicMatchScorer:
    """Scores one observation pair against one entity-type policy."""

    def __init__(self, policy: ResolutionPolicy) -> None:
        self._policy = policy

    def score(self, left: EntityObservation, right: EntityObservation) -> MatchScore:
        entity_policy = self._policy.for_entity(left.entity_type)
        evidence: list[MatchEvidence] = []
        reasons: list[ReasonCode] = []

        for signal, rule in _ordered(entity_policy):
            item, reason = self._evaluate(signal, rule, left, right, entity_policy)
            evidence.append(item)
            if reason is not None and reason not in reasons:
                reasons.append(reason)

        conflicts = self._conflicts(left, right, entity_policy)

        comparable = sum(
            item.weight for item in evidence if item.outcome is not SignalOutcome.NOT_COMPARABLE
        )
        earned = sum(item.contribution for item in evidence)
        penalty = sum(conflict.penalty for conflict in conflicts)
        raw = 0.0 if comparable <= 0.0 else (earned - penalty) / comparable
        score = min(1.0, max(0.0, raw))
        # How well the pair agreed before conflicts were subtracted. A pair that
        # agrees strongly *and* conflicts hard is a question for a person, not a
        # pair to drop — the penalty alone would push it under the floor and it
        # would never be seen.
        agreement = 0.0 if comparable <= 0.0 else earned / comparable

        band = entity_policy.band_for(score)
        recommendation, outcome_reasons = _recommend(
            score, agreement, comparable, conflicts, entity_policy
        )
        for reason in outcome_reasons:
            if reason not in reasons:
                reasons.append(reason)

        return MatchScore(
            score=score,
            evidence_weight=comparable,
            confidence=band.band,
            confidence_floor=band.minimum_score,
            recommendation=recommendation,
            policy_version=self._policy.policy_version,
            reasons=tuple(reasons),
            evidence=tuple(evidence),
            conflicts=tuple(conflicts),
        )

    # -- signals ----------------------------------------------------------

    def _evaluate(
        self,
        signal: MatchSignal,
        rule: SignalRule,
        left: EntityObservation,
        right: EntityObservation,
        entity_policy: EntityTypePolicy,
    ) -> tuple[MatchEvidence, ReasonCode | None]:
        if signal in _EXACT_ATTRIBUTES:
            return self._exact(signal, rule, left, right, _EXACT_ATTRIBUTES[signal])
        if signal is MatchSignal.EXACT_SOURCE_IDENTIFIER:
            return self._source_identifier(rule, left, right)
        if signal is MatchSignal.NAME_SIMILARITY:
            return self._similar(
                signal, rule, left, right, ATTR_NAME, ReasonCode.NAME_SIMILARITY_ABOVE_THRESHOLD
            )
        if signal is MatchSignal.ADDRESS_SIMILARITY:
            return self._similar(
                signal,
                rule,
                left,
                right,
                ATTR_ADDRESS,
                ReasonCode.ADDRESS_SIMILARITY_ABOVE_THRESHOLD,
            )
        if signal is MatchSignal.TEMPORAL_CONSISTENCY:
            return self._temporal(rule, left, right)
        if signal is MatchSignal.SOURCE_RELIABILITY:
            return self._reliability(rule, left, right)
        if signal is MatchSignal.CROSS_SOURCE_CONSISTENCY:
            return self._cross_source(rule, left, right)
        return (
            MatchEvidence(signal, rule.attribute, SignalOutcome.NOT_COMPARABLE, rule.weight, 0.0),
            None,
        )

    def _exact(
        self,
        signal: MatchSignal,
        rule: SignalRule,
        left: EntityObservation,
        right: EntityObservation,
        attribute: str,
    ) -> tuple[MatchEvidence, ReasonCode | None]:
        a, b = left.attributes.get(attribute), right.attributes.get(attribute)
        if not a or not b:
            return (
                MatchEvidence(
                    signal, rule.attribute, SignalOutcome.NOT_COMPARABLE, rule.weight, 0.0
                ),
                None,
            )
        if a == b:
            return (
                MatchEvidence(
                    signal, rule.attribute, SignalOutcome.AGREED, rule.weight, rule.weight
                ),
                _EXACT_REASONS[signal],
            )
        return (
            MatchEvidence(signal, rule.attribute, SignalOutcome.DISAGREED, rule.weight, 0.0),
            None,
        )

    def _source_identifier(
        self, rule: SignalRule, left: EntityObservation, right: EntityObservation
    ) -> tuple[MatchEvidence, ReasonCode | None]:
        """One side quoting the other's stable identifier is an exact match.

        Comparable only when at least one side actually carries a cross-source
        reference: two sources that never quote each other say nothing here.
        """
        signal = MatchSignal.EXACT_SOURCE_IDENTIFIER
        left_ref = left.attributes.get(ATTR_SOURCE_ENTITY_REF)
        right_ref = right.attributes.get(ATTR_SOURCE_ENTITY_REF)
        if not left_ref and not right_ref:
            return (
                MatchEvidence(
                    signal, rule.attribute, SignalOutcome.NOT_COMPARABLE, rule.weight, 0.0
                ),
                None,
            )

        left_key = canonical_entity_key(left.entity_key)
        right_key = canonical_entity_key(right.entity_key)
        agreed = (left_ref is not None and left_ref == right_key) or (
            right_ref is not None and right_ref == left_key
        )
        if not agreed and left_ref and right_ref:
            agreed = left_ref == right_ref
        if agreed:
            return (
                MatchEvidence(
                    signal, rule.attribute, SignalOutcome.AGREED, rule.weight, rule.weight
                ),
                ReasonCode.SOURCE_IDENTIFIER_MATCH,
            )
        return (
            MatchEvidence(signal, rule.attribute, SignalOutcome.DISAGREED, rule.weight, 0.0),
            None,
        )

    def _similar(
        self,
        signal: MatchSignal,
        rule: SignalRule,
        left: EntityObservation,
        right: EntityObservation,
        attribute: str,
        reason: ReasonCode,
    ) -> tuple[MatchEvidence, ReasonCode | None]:
        a, b = left.attributes.get(attribute), right.attributes.get(attribute)
        if not a or not b:
            return (
                MatchEvidence(
                    signal, rule.attribute, SignalOutcome.NOT_COMPARABLE, rule.weight, 0.0
                ),
                None,
            )
        ratio = text_similarity(a, b)
        threshold = rule.minimum_similarity if rule.minimum_similarity is not None else 1.0
        if ratio >= threshold:
            return (
                MatchEvidence(
                    signal, rule.attribute, SignalOutcome.AGREED, rule.weight, rule.weight, ratio
                ),
                reason,
            )
        return (
            MatchEvidence(
                signal, rule.attribute, SignalOutcome.DISAGREED, rule.weight, 0.0, ratio
            ),
            None,
        )

    def _temporal(
        self, rule: SignalRule, left: EntityObservation, right: EntityObservation
    ) -> tuple[MatchEvidence, ReasonCode | None]:
        """Do the two observation windows sit close enough in time to be one entity?

        A register entry from years after the calls it is matched against is a
        weaker claim than one contemporaneous with them. Windows that overlap
        are consistent; disjoint windows are consistent only within the policy's
        maximum gap.
        """
        signal = MatchSignal.TEMPORAL_CONSISTENCY
        gap = temporal_gap_days(left, right)
        if gap is None:
            return (
                MatchEvidence(
                    signal, rule.attribute, SignalOutcome.NOT_COMPARABLE, rule.weight, 0.0
                ),
                None,
            )
        limit = rule.maximum_gap_days if rule.maximum_gap_days is not None else 0
        if gap <= limit:
            return (
                MatchEvidence(
                    signal, rule.attribute, SignalOutcome.AGREED, rule.weight, rule.weight
                ),
                ReasonCode.TEMPORAL_CONSISTENT,
            )
        return (
            MatchEvidence(signal, rule.attribute, SignalOutcome.DISAGREED, rule.weight, 0.0),
            None,
        )

    def _reliability(
        self, rule: SignalRule, left: EntityObservation, right: EntityObservation
    ) -> tuple[MatchEvidence, ReasonCode | None]:
        """Always comparable: how much the two sources are trusted is policy data."""
        combined = self._policy.reliability_of(left.source_id) * self._policy.reliability_of(
            right.source_id
        )
        return (
            MatchEvidence(
                MatchSignal.SOURCE_RELIABILITY,
                rule.attribute,
                SignalOutcome.AGREED,
                rule.weight,
                rule.weight * combined,
                combined,
            ),
            None,
        )

    def _cross_source(
        self, rule: SignalRule, left: EntityObservation, right: EntityObservation
    ) -> tuple[MatchEvidence, ReasonCode | None]:
        """Independent corroboration: two different sources agreeing carries weight.

        Two rows of one export agreeing is one source repeating itself, so this
        signal is comparable but unearned in that case.
        """
        signal = MatchSignal.CROSS_SOURCE_CONSISTENCY
        if left.source_id == right.source_id:
            return (
                MatchEvidence(signal, rule.attribute, SignalOutcome.DISAGREED, rule.weight, 0.0),
                None,
            )
        agreements, disagreements = _attribute_agreement(left, right)
        if agreements and not disagreements:
            return (
                MatchEvidence(
                    signal, rule.attribute, SignalOutcome.AGREED, rule.weight, rule.weight
                ),
                ReasonCode.CROSS_SOURCE_AGREEMENT,
            )
        return (
            MatchEvidence(signal, rule.attribute, SignalOutcome.DISAGREED, rule.weight, 0.0),
            None,
        )

    # -- conflicts --------------------------------------------------------

    def _conflicts(
        self, left: EntityObservation, right: EntityObservation, entity_policy: EntityTypePolicy
    ) -> list[ResolutionConflict]:
        conflicts: list[ResolutionConflict] = []
        for attribute, rule in sorted(entity_policy.conflicts.items()):
            if attribute == ATTR_NAME:
                conflict = self._name_conflict(left, right, rule)
            elif attribute == "observed_at":
                conflict = self._temporal_conflict(left, right, rule, entity_policy)
            else:
                conflict = self._value_conflict(left, right, rule, attribute)
            if conflict is not None:
                conflicts.append(conflict)
        return conflicts

    def _value_conflict(
        self, left: EntityObservation, right: EntityObservation, rule, attribute: str
    ) -> ResolutionConflict | None:
        a, b = left.attributes.get(attribute), right.attributes.get(attribute)
        if not a or not b or a == b:
            return None
        return ResolutionConflict(
            attribute=attribute,
            rule=rule.rule,
            penalty=rule.penalty,
            blocks_auto_accept=rule.blocks_auto_accept,
        )

    def _name_conflict(
        self, left: EntityObservation, right: EntityObservation, rule
    ) -> ResolutionConflict | None:
        """Names disagree only when they are far apart.

        Between the conflict ceiling and the similarity threshold sits a
        deliberate neutral band: `R. Kulkarni` and `Rohit Kulkarni` neither
        prove nor disprove the same person.
        """
        a, b = left.attributes.get(ATTR_NAME), right.attributes.get(ATTR_NAME)
        if not a or not b:
            return None
        ceiling = rule.maximum_similarity if rule.maximum_similarity is not None else 0.0
        ratio = text_similarity(a, b)
        if ratio > ceiling:
            return None
        return ResolutionConflict(
            attribute=ATTR_NAME,
            rule=rule.rule,
            penalty=rule.penalty,
            blocks_auto_accept=rule.blocks_auto_accept,
            similarity=ratio,
        )

    def _temporal_conflict(
        self,
        left: EntityObservation,
        right: EntityObservation,
        rule,
        entity_policy: EntityTypePolicy,
    ) -> ResolutionConflict | None:
        signal_rule = entity_policy.signal(MatchSignal.TEMPORAL_CONSISTENCY)
        limit = (
            signal_rule.maximum_gap_days
            if signal_rule is not None and signal_rule.maximum_gap_days is not None
            else None
        )
        gap = temporal_gap_days(left, right)
        if gap is None or limit is None or gap <= limit:
            return None
        return ResolutionConflict(
            attribute="observed_at",
            rule=rule.rule,
            penalty=rule.penalty,
            blocks_auto_accept=rule.blocks_auto_accept,
        )


def _ordered(entity_policy: EntityTypePolicy) -> list[tuple[MatchSignal, SignalRule]]:
    """Signals in enum order, so evidence lists are stable across runs."""
    return [
        (signal, entity_policy.signals[signal])
        for signal in MatchSignal
        if signal in entity_policy.signals
    ]


def _recommend(
    score: float,
    agreement: float,
    comparable: float,
    conflicts: list[ResolutionConflict],
    entity_policy: EntityTypePolicy,
) -> tuple[Recommendation, list[ReasonCode]]:
    """Turn two numbers and a conflict list into one proposal.

    Order matters. A blocking conflict is decided on the *unpenalised*
    agreement, because the penalty exists to stop an automatic merge — not to
    hide the pair. One number registered to two different identity references is
    exactly what an investigator needs to see.
    """
    thresholds = entity_policy.thresholds
    blocking = [conflict for conflict in conflicts if conflict.blocks_auto_accept]

    if blocking and agreement >= thresholds.review_floor:
        return Recommendation.CONFLICT, [ReasonCode.CONFLICT_BLOCKS_AUTO_ACCEPT]

    if score < thresholds.review_floor:
        return Recommendation.UNRESOLVED, [ReasonCode.SCORE_BELOW_REVIEW_FLOOR]

    if blocking:
        return Recommendation.CONFLICT, [ReasonCode.CONFLICT_BLOCKS_AUTO_ACCEPT]

    if score < thresholds.auto_accept:
        return Recommendation.POSSIBLE_MATCH, [ReasonCode.SCORE_IN_REVIEW_BAND]

    reasons = [ReasonCode.SCORE_ABOVE_AUTO_ACCEPT]
    if comparable < thresholds.minimum_evidence_weight:
        # Agreement on too little to act on alone.
        reasons.append(ReasonCode.INSUFFICIENT_EVIDENCE_WEIGHT)
        return Recommendation.POSSIBLE_MATCH, reasons
    return Recommendation.MATCH, reasons


def temporal_gap_days(left: EntityObservation, right: EntityObservation) -> float | None:
    """Days between the two observation windows; 0.0 when they overlap.

    None when either side carries no usable timestamp — not comparable, which is
    different from inconsistent.
    """
    left_window = _window(left)
    right_window = _window(right)
    if left_window is None or right_window is None:
        return None
    left_start, left_end = left_window
    right_start, right_end = right_window
    if left_start <= right_end and right_start <= left_end:
        return 0.0
    gap = (
        (right_start - left_end).total_seconds()
        if left_end < right_start
        else (left_start - right_end).total_seconds()
    )
    return abs(gap) / _SECONDS_PER_DAY


def _window(observation: EntityObservation):
    start = observation.attributes.get("observed_from") or observation.observed_at
    end = observation.attributes.get("observed_to") or start
    try:
        parsed_start = parse_iso(start)
        parsed_end = parse_iso(end)
    except (TypeError, ValueError):
        return None
    return (parsed_start, parsed_end) if parsed_start <= parsed_end else (parsed_end, parsed_start)


def _attribute_agreement(
    left: EntityObservation, right: EntityObservation
) -> tuple[list[str], list[str]]:
    """Which shared attributes agree and which do not. Timestamps are handled separately."""
    ignored = {"observed_from", "observed_to"}
    shared = (set(left.attributes) & set(right.attributes)) - ignored
    agreements = [key for key in sorted(shared) if left.attributes[key] == right.attributes[key]]
    disagreements = [
        key for key in sorted(shared) if left.attributes[key] != right.attributes[key]
    ]
    return agreements, disagreements
