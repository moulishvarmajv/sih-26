"""Entity resolution application service.

The only path between the API and resolution state, and the place where the
whole subsystem's order of operations lives:

    authorize -> extract -> block -> score -> decide -> persist -> project -> audit

Resolution is an explicit processing step. It is not reachable from evidence
ingestion or graph persistence, and nothing runs it implicitly: reading a case's
resolutions never computes any.

Three properties this file is responsible for:

- **Authorization comes first, and it is per evidence item.** A resolution is
  derived from two evidence items, so a reader must be authorized for both.
  Evidence the reader may not see never enters the extraction set, rather than
  being filtered out of the answer afterwards.
- **Nothing merges silently.** Auto-acceptance requires a score above the
  policy's threshold, enough comparable evidence, no conflict that blocks it,
  and no rival candidate within the ambiguity margin. Anything else is recorded
  and routed to a person.
- **A run never overwrites history.** Re-running with unchanged inputs is a
  no-op; changed inputs supersede the previous decision and keep it readable.
  A resolution a person rejected is never re-accepted automatically.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from app.core.audit.event_store import ActorType, EventDraft, EventStore, FlightRecorderEvent
from app.core.domain.agency import AgencyContext
from app.core.domain.authorization import AuthorizationDecision
from app.core.domain.case import Case
from app.core.domain.identity import User
from app.core.evidence.models import EvidenceRecord
from app.core.evidence.object_store import EvidenceObjectStore
from app.core.evidence.repository import EvidenceRepository
from app.core.graph.repository import GraphRepository, GraphUnavailable
from app.core.resolution import projection
from app.core.resolution.candidates import CandidateGenerator
from app.core.resolution.extraction import ObservationExtractor, default_extractors
from app.core.resolution.models import (
    DecidedBy,
    EntityObservation,
    EntityResolutionCandidate,
    EntityResolutionDecision,
    EntityType,
    MatchScore,
    ReasonCode,
    Recommendation,
    ResolutionReview,
    ResolutionStatus,
    ReviewAction,
    input_fingerprint,
    resolution_id_for,
    with_reasons,
)
from app.core.resolution.policy import ResolutionPolicy
from app.core.resolution.repository import ResolutionRepository
from app.core.resolution.scoring import DeterministicMatchScorer
from app.infrastructure.clock import utc_now_iso
from app.security.privacy.masking import mask_payload
from app.security.privacy.policy import PrivacyPolicy
from app.security.service import SecurityService

ACTION_RUN_RESOLUTION = "RUN_ENTITY_RESOLUTION"
ACTION_VIEW_RESOLUTION = "VIEW_ENTITY_RESOLUTION"
ACTION_REVIEW_RESOLUTION = "REVIEW_ENTITY_RESOLUTION"

#: Evidence field names carry into resolution under canonical attribute names.
#: A reader whose evidence decision redacts `caller` must not read the entity
#: key that identifies the same person in a resolution response.
EVIDENCE_FIELD_TO_ENTITY_ATTRIBUTE: Mapping[str, tuple[str, ...]] = {
    "caller": ("phone",),
    "callee": ("phone",),
    "imei": ("imei",),
    "imsi": ("imsi",),
    "msisdn": ("phone",),
    "subscriber_name": ("name", "entity_key"),
    "subscriber_address": ("address",),
    "account_number": ("account_number",),
    "national_id_ref": ("national_id_ref",),
}

#: The field name an entity key is masked under. It is not in the policy's
#: partial-mask list, so a masked label is redacted outright rather than keeping
#: a recognisable tail — an investigator still tells two masked entities apart
#: by `entity_ref`, which is a hash and discloses nothing.
_ENTITY_KEY_FIELD = "entity_key"


class ResolutionAccessDenied(Exception):
    """Raised when authorization denies resolution access. Carries no resolution data."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ResolutionNotFound(Exception):
    """Raised when a resolution does not exist in the case being asked about."""


class ResolutionNotOpen(Exception):
    """Raised when a review targets a resolution that is not awaiting review."""


@dataclass(frozen=True)
class ResolutionRunSummary:
    case_id: str
    evidence_considered: int
    evidence_excluded: int
    observations: int
    candidates: int
    auto_accepted: int
    review_required: int
    unresolved: int
    superseded: int
    unchanged: int
    links_projected: int
    graph_available: bool
    policy_version: str


@dataclass(frozen=True)
class ResolutionView:
    """One decision as a reader is allowed to see it."""

    decision: EntityResolutionDecision
    candidate: EntityResolutionCandidate | None
    reviews: tuple[ResolutionReview, ...]
    left_label: str
    right_label: str
    masked_fields: tuple[str, ...]


class EntityResolutionService:
    def __init__(
        self,
        resolution_repository: ResolutionRepository,
        evidence_repository: EvidenceRepository,
        object_store: EvidenceObjectStore,
        graph_repository: GraphRepository,
        security: SecurityService,
        event_store: EventStore,
        policy: ResolutionPolicy,
        privacy: PrivacyPolicy,
        extractors: Mapping[str, ObservationExtractor] | None = None,
        clock: Callable[[], str] = utc_now_iso,
    ) -> None:
        self._resolutions = resolution_repository
        self._evidence = evidence_repository
        self._objects = object_store
        self._graph = graph_repository
        self._security = security
        self._events = event_store
        self._policy = policy
        self._privacy = privacy
        self._extractors = dict(extractors) if extractors is not None else default_extractors()
        self._scorer = DeterministicMatchScorer(policy)
        self._clock = clock

    # -- run --------------------------------------------------------------

    def run(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        entity_type: EntityType = EntityType.PERSON,
    ) -> ResolutionRunSummary:
        """Resolve entities across the evidence this reader is authorized for."""
        case_decision = self._authorize_case(user, context, case, ACTION_RUN_RESOLUTION)
        correlation = case_decision.correlation_id
        self._record(
            FlightRecorderEvent.ENTITY_RESOLUTION_STARTED,
            user.id,
            case.id,
            correlation,
            {"entity_type": entity_type.value, "policy_version": self._policy.policy_version},
        )

        try:
            authorized, excluded, _ = self._authorized_evidence(user, context, case)
            observations = self._observe(authorized)
            entity_policy = self._policy.for_entity(entity_type)
            candidates = CandidateGenerator(entity_policy).generate(
                [o for o in observations if o.entity_type is entity_type], self._clock()
            )
            by_observation = {o.observation_id: o for o in observations}
            scored = self._score_all(candidates, by_observation)
            outcomes = self._decide_all(candidates, scored, entity_policy)
            summary_counts = self._persist(user, case, candidates, outcomes, correlation)
        except Exception as exc:
            self._record(
                FlightRecorderEvent.ENTITY_RESOLUTION_FAILED,
                user.id,
                case.id,
                correlation,
                {"error_code": type(exc).__name__},
            )
            raise

        projected, graph_available = self._project(user, case, correlation)
        summary = ResolutionRunSummary(
            case_id=case.id,
            evidence_considered=len(authorized),
            evidence_excluded=excluded,
            observations=len(observations),
            candidates=len(candidates),
            links_projected=projected,
            graph_available=graph_available,
            policy_version=self._policy.policy_version,
            **summary_counts,
        )
        self._record(
            FlightRecorderEvent.ENTITY_RESOLUTION_COMPLETED,
            user.id,
            case.id,
            correlation,
            {
                "entity_type": entity_type.value,
                "policy_version": self._policy.policy_version,
                "evidence_considered": summary.evidence_considered,
                "evidence_excluded": summary.evidence_excluded,
                "observations": summary.observations,
                "candidates": summary.candidates,
                "auto_accepted": summary.auto_accepted,
                "review_required": summary.review_required,
                "unresolved": summary.unresolved,
                "superseded": summary.superseded,
                "unchanged": summary.unchanged,
                "links_projected": summary.links_projected,
                "graph_available": summary.graph_available,
            },
        )
        return summary

    # -- reads ------------------------------------------------------------

    def list_resolutions(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        statuses: Sequence[ResolutionStatus] | None = None,
    ) -> list[ResolutionView]:
        """Read a case's resolutions. Never computes anything."""
        self._authorize_case(user, context, case, ACTION_VIEW_RESOLUTION)
        allowed, _, masked = self._authorized_evidence(user, context, case)
        allowed_ids = {record.id for record, _ in allowed}
        views = []
        for decision in self._resolutions.list_decisions(case.id, statuses):
            if not self._readable(decision, allowed_ids):
                continue
            views.append(self._view(decision, masked))
        return views

    def get_resolution(
        self, user: User, context: AgencyContext, case: Case, resolution_id: str
    ) -> ResolutionView:
        self._authorize_case(user, context, case, ACTION_VIEW_RESOLUTION)
        decision = self._require_decision(case, resolution_id)
        allowed, _, masked = self._authorized_evidence(user, context, case)
        if not self._readable(decision, {record.id for record, _ in allowed}):
            self._record(
                FlightRecorderEvent.ENTITY_RESOLUTION_ACCESS_DENIED,
                user.id,
                case.id,
                "-",
                {"resolution_id": resolution_id, "reason": "EVIDENCE_NOT_AUTHORIZED"},
            )
            raise ResolutionAccessDenied("EVIDENCE_NOT_AUTHORIZED")
        return self._view(decision, masked)

    # -- review -----------------------------------------------------------

    def review(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        resolution_id: str,
        action: ReviewAction,
        reason: str | None = None,
    ) -> ResolutionView:
        """Record a human action. Deferral leaves the resolution open by design."""
        decision_facts = self._security.authorize_action(
            user, context, ACTION_REVIEW_RESOLUTION, case=case
        )
        if not decision_facts.grants_access:
            self._record(
                FlightRecorderEvent.ENTITY_RESOLUTION_ACCESS_DENIED,
                user.id,
                case.id,
                decision_facts.correlation_id,
                {"resolution_id": resolution_id, "reason": decision_facts.reason.value},
            )
            raise ResolutionAccessDenied(decision_facts.reason.value)

        decision = self._require_decision(case, resolution_id)
        allowed, _, masked = self._authorized_evidence(user, context, case)
        if not self._readable(decision, {record.id for record, _ in allowed}):
            raise ResolutionAccessDenied("EVIDENCE_NOT_AUTHORIZED")
        if not decision.is_open:
            raise ResolutionNotOpen(
                f"resolution '{resolution_id}' is {decision.status.value}"
            )

        now = self._clock()
        self._resolutions.add_review(
            ResolutionReview(
                review_id=f"REV-{resolution_id}-{len(self._resolutions.list_reviews(resolution_id)) + 1}",
                resolution_id=resolution_id,
                case_id=case.id,
                reviewer_id=user.id,
                action=action,
                reviewed_at=now,
                reason=reason,
            )
        )

        if action is ReviewAction.DEFER:
            # Deferral is a recorded look, not an outcome: the resolution stays
            # REVIEW_REQUIRED so it remains in the queue.
            self._record(
                FlightRecorderEvent.ENTITY_RESOLUTION_DEFERRED,
                user.id,
                case.id,
                decision_facts.correlation_id,
                {"resolution_id": resolution_id, "reviewer_id": user.id},
            )
            return self._view(self._require_decision(case, resolution_id), masked)

        status = (
            ResolutionStatus.APPROVED
            if action is ReviewAction.APPROVE
            else ResolutionStatus.REJECTED
        )
        updated = self._resolutions.update_status(
            resolution_id=resolution_id,
            status=status,
            decided_at=now,
            decided_by=user.id,
            decision_actor=DecidedBy.HUMAN.value,
            decision_reason=reason,
        )

        if status is ResolutionStatus.APPROVED:
            self._project_decisions([updated], user, case, decision_facts.correlation_id)
        else:
            self._restate_link(updated, status.value, now)

        self._record(
            FlightRecorderEvent.ENTITY_RESOLUTION_APPROVED
            if status is ResolutionStatus.APPROVED
            else FlightRecorderEvent.ENTITY_RESOLUTION_REJECTED,
            user.id,
            case.id,
            decision_facts.correlation_id,
            {
                "resolution_id": resolution_id,
                "lineage_id": updated.lineage_id,
                "reviewer_id": user.id,
                "decision_actor": DecidedBy.HUMAN.value,
                "score": round(updated.score.score, 4),
                "policy_version": updated.policy_version,
            },
        )
        return self._view(updated, masked)

    # -- pipeline ---------------------------------------------------------

    def _observe(self, records: Sequence[tuple[EvidenceRecord, Any]]) -> list[EntityObservation]:
        observations: list[EntityObservation] = []
        for record, version in records:
            extractor = self._extractors.get(record.source_id)
            if extractor is None:
                continue  # no extractor for this source: skipped, never guessed at
            payload = json.loads(self._objects.get(version.payload_ref))
            observations.extend(extractor.extract(record, version, payload))
        return sorted(observations, key=lambda observation: observation.observation_id)

    def _score_all(
        self,
        candidates: Sequence[EntityResolutionCandidate],
        by_observation: Mapping[str, EntityObservation],
    ) -> dict[str, MatchScore]:
        scores: dict[str, MatchScore] = {}
        for candidate in candidates:
            left = by_observation[candidate.left.observation_id]
            right = by_observation[candidate.right.observation_id]
            scores[candidate.candidate_id] = self._scorer.score(left, right)
        return scores

    def _decide_all(
        self,
        candidates: Sequence[EntityResolutionCandidate],
        scores: Mapping[str, MatchScore],
        entity_policy,
    ) -> dict[str, tuple[ResolutionStatus, MatchScore]]:
        """Turn scores into statuses, including the cross-candidate ambiguity rule."""
        ambiguous = self._ambiguous(candidates, scores, entity_policy.thresholds.ambiguity_margin)
        outcomes: dict[str, tuple[ResolutionStatus, MatchScore]] = {}
        for candidate in candidates:
            score = scores[candidate.candidate_id]
            if score.recommendation is Recommendation.UNRESOLVED:
                outcomes[candidate.candidate_id] = (ResolutionStatus.CANDIDATE, score)
                continue
            if candidate.candidate_id in ambiguous:
                outcomes[candidate.candidate_id] = (
                    ResolutionStatus.REVIEW_REQUIRED,
                    with_reasons(
                        score,
                        ReasonCode.AMBIGUOUS_ALTERNATIVE,
                        recommendation=Recommendation.REVIEW_REQUIRED,
                    ),
                )
                continue
            if score.recommendation is Recommendation.MATCH:
                outcomes[candidate.candidate_id] = (ResolutionStatus.AUTO_ACCEPTED, score)
                continue
            outcomes[candidate.candidate_id] = (ResolutionStatus.REVIEW_REQUIRED, score)
        return outcomes

    def _ambiguous(
        self,
        candidates: Sequence[EntityResolutionCandidate],
        scores: Mapping[str, MatchScore],
        margin: float,
    ) -> set[str]:
        """Candidate ids no automated decision may accept, because a rival is too close.

        Two candidates for the same observation scoring 0.91 and 0.89 are not a
        decision. Both go to a person; picking the higher one would be an
        arbitrary tie-break presented as a conclusion.
        """
        by_observation: dict[str, list[EntityResolutionCandidate]] = {}
        for candidate in candidates:
            if scores[candidate.candidate_id].recommendation is Recommendation.UNRESOLVED:
                continue
            for ref in (candidate.left, candidate.right):
                by_observation.setdefault(ref.observation_id, []).append(candidate)

        ambiguous: set[str] = set()
        for rivals in by_observation.values():
            if len(rivals) < 2:
                continue
            ordered = sorted(
                rivals, key=lambda c: (-scores[c.candidate_id].score, c.candidate_id)
            )
            best = scores[ordered[0].candidate_id].score
            close = [c for c in ordered if best - scores[c.candidate_id].score <= margin]
            if len(close) > 1:
                ambiguous.update(candidate.candidate_id for candidate in close)
        return ambiguous

    def _persist(
        self,
        user: User,
        case: Case,
        candidates: Sequence[EntityResolutionCandidate],
        outcomes: Mapping[str, tuple[ResolutionStatus, MatchScore]],
        correlation: str,
    ) -> dict[str, int]:
        counts = {
            "auto_accepted": 0,
            "review_required": 0,
            "unresolved": 0,
            "superseded": 0,
            "unchanged": 0,
        }
        now = self._clock()
        for candidate in candidates:
            self._resolutions.save_candidate(candidate)
            status, score = outcomes[candidate.candidate_id]
            fingerprint = input_fingerprint(
                candidate.left, candidate.right, self._policy.policy_version
            )
            live = self._resolutions.get_live_decision(candidate.lineage_id)

            if live is not None and live.input_fingerprint == fingerprint:
                # Same inputs and same policy: re-running changes nothing, and
                # in particular does not reopen a decision a person made.
                counts["unchanged"] += 1
                continue

            version = 1 if live is None else live.resolution_version + 1
            if live is not None:
                counts["superseded"] += 1
                status, score = self._carry_forward(live, status, score)

            self._record(
                FlightRecorderEvent.ENTITY_RESOLUTION_CANDIDATE_CREATED,
                user.id,
                case.id,
                correlation,
                {
                    "candidate_id": candidate.candidate_id,
                    "lineage_id": candidate.lineage_id,
                    "blocking_strategy": candidate.blocking_strategy.value,
                    "entity_type": candidate.entity_type.value,
                },
            )

            resolution_id = resolution_id_for(candidate.lineage_id, version)
            auto = status is ResolutionStatus.AUTO_ACCEPTED
            decision = EntityResolutionDecision(
                resolution_id=resolution_id,
                lineage_id=candidate.lineage_id,
                resolution_version=version,
                case_id=case.id,
                entity_type=candidate.entity_type,
                candidate_id=candidate.candidate_id,
                left=candidate.left,
                right=candidate.right,
                status=status,
                score=score,
                policy_version=self._policy.policy_version,
                input_fingerprint=fingerprint,
                created_at=now,
                decided_at=now if auto else None,
                decided_by=DecidedBy.SYSTEM.value if auto else None,
                decision_actor=DecidedBy.SYSTEM if auto else None,
            )
            self._resolutions.save_decision(decision)

            if live is not None:
                self._restate_link(live, ResolutionStatus.SUPERSEDED.value, now)
                self._record(
                    FlightRecorderEvent.ENTITY_RESOLUTION_SUPERSEDED,
                    user.id,
                    case.id,
                    correlation,
                    {
                        "resolution_id": live.resolution_id,
                        "superseded_by": resolution_id,
                        "previous_status": live.status.value,
                    },
                )

            counts[_COUNT_KEYS[status]] += 1
            self._record(
                _OUTCOME_EVENTS[status],
                user.id,
                case.id,
                correlation,
                {
                    "resolution_id": resolution_id,
                    "lineage_id": candidate.lineage_id,
                    "status": status.value,
                    "recommendation": score.recommendation.value,
                    "score": round(score.score, 4),
                    "evidence_weight": round(score.evidence_weight, 4),
                    "confidence": score.confidence.value,
                    "reasons": [reason.value for reason in score.reasons],
                    "conflicts": [conflict.rule for conflict in score.conflicts],
                    "policy_version": self._policy.policy_version,
                },
            )
        return counts

    def _carry_forward(
        self, live: EntityResolutionDecision, status: ResolutionStatus, score: MatchScore
    ) -> tuple[ResolutionStatus, MatchScore]:
        """A person's judgement is never silently overturned by a later run.

        New evidence can change what the system computes, but a resolution a
        reviewer rejected goes back to that reviewer rather than being
        auto-accepted on the strength of the new inputs.
        """
        reasons = [ReasonCode.SUPERSEDED_BY_NEW_EVIDENCE]
        if live.status is ResolutionStatus.REJECTED:
            reasons.append(ReasonCode.PRIOR_HUMAN_REJECTION)
            if status is not ResolutionStatus.CANDIDATE:
                status = ResolutionStatus.REVIEW_REQUIRED
        elif live.status is ResolutionStatus.APPROVED and status is ResolutionStatus.CANDIDATE:
            # The new inputs no longer support what a person approved: ask again
            # rather than dropping the identity link without telling anyone.
            status = ResolutionStatus.REVIEW_REQUIRED
        return status, with_reasons(score, *reasons)

    # -- graph ------------------------------------------------------------

    def _project(self, user: User, case: Case, correlation: str) -> tuple[int, bool]:
        accepted = [
            decision
            for decision in self._resolutions.list_decisions(
                case.id, (ResolutionStatus.AUTO_ACCEPTED, ResolutionStatus.APPROVED)
            )
        ]
        return self._project_decisions(accepted, user, case, correlation)

    def _project_decisions(
        self,
        decisions: Sequence[EntityResolutionDecision],
        user: User,
        case: Case,
        correlation: str,
    ) -> tuple[int, bool]:
        """Write inferred links. A graph outage does not invalidate the decisions."""
        nodes, links = projection.project(decisions)
        if not links:
            return 0, True
        try:
            self._graph.initialize_schema()
            self._graph.upsert_nodes(nodes)
            written = self._graph.upsert_relationships(links)
        except GraphUnavailable:
            self._record(
                FlightRecorderEvent.GRAPH_INGESTION_FAILED,
                user.id,
                case.id,
                correlation,
                {"stage": "ENTITY_RESOLUTION_PROJECTION", "error_code": "GRAPH_UNAVAILABLE"},
            )
            return 0, False
        self._record(
            FlightRecorderEvent.ENTITY_RESOLUTION_PROJECTED,
            user.id,
            case.id,
            correlation,
            {
                "links_written": written,
                "trust_class": "INFERRED",
                "resolution_ids": [decision.resolution_id for decision in decisions],
            },
        )
        return written, True

    def _restate_link(
        self, decision: EntityResolutionDecision, status: str, updated_at: str
    ) -> None:
        """Mark an inferred link rejected or superseded. Never deletes it."""
        try:
            self._graph.update_inferred_link_status(decision.resolution_id, status, updated_at)
        except GraphUnavailable:
            return  # the decision stands; the graph catches up on the next run

    # -- authorization ----------------------------------------------------

    def _authorize_case(
        self, user: User, context: AgencyContext, case: Case, action: str
    ) -> AuthorizationDecision:
        decision = self._security.authorize_case_access(user, context, case, action)
        if not decision.grants_access:
            self._record(
                FlightRecorderEvent.ENTITY_RESOLUTION_ACCESS_DENIED,
                user.id,
                case.id,
                decision.correlation_id,
                {"reason": decision.reason.value, "scope": "CASE", "action": action},
            )
            raise ResolutionAccessDenied(decision.reason.value)
        return decision

    def _authorized_evidence(
        self, user: User, context: AgencyContext, case: Case
    ) -> tuple[list[tuple[EvidenceRecord, Any]], int, tuple[str, ...]]:
        """Evidence this reader may use, the count excluded, and the fields masked.

        Excluded evidence is dropped before extraction, so an unauthorized item
        never contributes an observation, a candidate or a score.
        """
        authorized: list[tuple[EvidenceRecord, Any]] = []
        redacted: set[str] = set()
        excluded = 0
        for record in self._evidence.list_evidence_for_case(case.id):
            decision = self._security.authorize_evidence_access(
                user, context, case, record, ACTION_VIEW_RESOLUTION
            )
            if not decision.grants_access:
                excluded += 1
                continue
            redacted.update(decision.redacted_fields)
            version = self._evidence.get_latest_version(record.id)
            if version is None:
                continue
            authorized.append((record, version))
        return authorized, excluded, tuple(sorted(redacted))

    def _readable(self, decision: EntityResolutionDecision, allowed: set[str]) -> bool:
        """A resolution is readable only when *both* its evidence items are."""
        return (
            decision.left.evidence_id in allowed and decision.right.evidence_id in allowed
        )

    # -- views ------------------------------------------------------------

    def _view(
        self, decision: EntityResolutionDecision, masked_fields: tuple[str, ...]
    ) -> ResolutionView:
        attributes = self._masked_attributes(masked_fields)
        mask_key = _ENTITY_KEY_FIELD in attributes
        return ResolutionView(
            decision=decision,
            candidate=self._resolutions.get_candidate(decision.candidate_id),
            reviews=tuple(self._resolutions.list_reviews(decision.resolution_id)),
            left_label=self._label(decision.left.entity_key, mask_key),
            right_label=self._label(decision.right.entity_key, mask_key),
            masked_fields=tuple(sorted(attributes)),
        )

    def _label(self, entity_key: str, masked: bool) -> str:
        """Mask through the privacy policy, never by a rule chosen here."""
        if not masked:
            return entity_key
        return mask_payload(
            {_ENTITY_KEY_FIELD: entity_key},
            (_ENTITY_KEY_FIELD,),
            self._privacy.partial_mask_fields,
        )[_ENTITY_KEY_FIELD]

    def _masked_attributes(self, redacted_fields: Iterable[str]) -> set[str]:
        attributes: set[str] = set()
        for field in redacted_fields:
            attributes.update(EVIDENCE_FIELD_TO_ENTITY_ATTRIBUTE.get(field, (field,)))
        return attributes

    def _require_decision(self, case: Case, resolution_id: str) -> EntityResolutionDecision:
        decision = self._resolutions.get_decision(resolution_id)
        if decision is None or decision.case_id != case.id:
            raise ResolutionNotFound(
                f"no resolution '{resolution_id}' in case '{case.id}'"
            )
        return decision

    def _record(
        self,
        event_type: FlightRecorderEvent,
        actor_id: str,
        case_id: str,
        correlation_id: str,
        payload: dict[str, Any],
    ) -> None:
        self._events.append(
            EventDraft(
                event_type=event_type,
                actor_id=actor_id,
                actor_type=ActorType.USER,
                correlation_id=correlation_id,
                case_id=case_id,
                payload=payload,
            )
        )


_OUTCOME_EVENTS = {
    ResolutionStatus.AUTO_ACCEPTED: FlightRecorderEvent.ENTITY_RESOLUTION_AUTO_ACCEPTED,
    ResolutionStatus.REVIEW_REQUIRED: FlightRecorderEvent.ENTITY_RESOLUTION_REVIEW_REQUIRED,
    ResolutionStatus.CANDIDATE: FlightRecorderEvent.ENTITY_RESOLUTION_UNRESOLVED,
}

_COUNT_KEYS = {
    ResolutionStatus.AUTO_ACCEPTED: "auto_accepted",
    ResolutionStatus.REVIEW_REQUIRED: "review_required",
    ResolutionStatus.CANDIDATE: "unresolved",
}
