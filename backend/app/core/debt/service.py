"""Evidence Debt application service.

The only path between the API and debt state, and the place this phase's
security property is established:

    raw investigation state
      -> case scope
      -> per-evidence authorization
      -> privacy
      -> authorized view
      -> detection
      -> weighting
      -> snapshot

Debt never reaches past the view for facts. A reader who may not see an evidence
item does not get debt computed from it and then filtered out — those facts were
never in scope, so the gaps they would have created do not exist as far as the
detectors are concerned. That is why a hidden conflict cannot surface as "one
redacted item": there is no item, no count and no contribution to a total.

Three consequences worth stating plainly, because they look like defects
otherwise:

- **Two readers legitimately get different totals.** Debt is debt *within the
  authorized scope*. A narrower reader sees fewer gaps, and their band is that
  scope's band.
- **A read computes but never persists.** `GET` recalculates over the reader's
  view and writes nothing, for the same reason viewing evidence never starts a
  processing run. Recording a snapshot is an explicit `POST`.
- **A persisted record belongs to the scope it was computed in.** Snapshots,
  items and trends are keyed on a fingerprint of the authorized evidence scope,
  so a narrow reader can never read, compare against, or overwrite a cleared
  reader's numbers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any, Callable, Iterable, Mapping, Sequence

from app.core.analytics.repository import AnalyticsRepository
from app.core.audit.event_store import ActorType, EventDraft, EventStore, FlightRecorderEvent
from app.core.debt import detectors
from app.core.debt.models import (
    DEBT_ENGINE_VERSION,
    DebtCategory,
    DebtChange,
    DebtFinding,
    DebtStatus,
    DebtWeighting,
    EvidenceDebtBreakdown,
    EvidenceDebtItem,
    EvidenceDebtSnapshot,
    build_breakdown,
    debt_identity,
    fact_fingerprint,
    scope_fingerprint,
    snapshot_identity,
)
from app.core.debt.policy import EvidenceDebtPolicy
from app.core.debt.repository import EvidenceDebtRepository
from app.core.debt.view import (
    CaseDebtView,
    DebtConflictView,
    DebtEvidenceView,
    DebtResolutionView,
    DebtResultView,
    DebtSignalView,
)
from app.core.domain.agency import AgencyContext
from app.core.domain.authorization import AuthorizationDecision
from app.core.domain.case import Case
from app.core.domain.identity import User
from app.core.evidence.models import AnalysisResult, EvidenceRecord
from app.core.evidence.object_store import EvidenceObjectStore
from app.core.evidence.repository import EvidenceRepository
from app.core.resolution.models import ResolutionStatus
from app.core.resolution.repository import ResolutionRepository
from app.infrastructure.clock import utc_now_iso
from app.security.service import SecurityService

ACTION_VIEW_DEBT = "VIEW_EVIDENCE_DEBT"
ACTION_RECALCULATE_DEBT = "RECALCULATE_EVIDENCE_DEBT"
ACTION_ACKNOWLEDGE_DEBT = "ACKNOWLEDGE_EVIDENCE_DEBT"

#: Identity decisions replaced by a newer version for the same pair. The live
#: decision carries the current state, so counting the superseded one as well
#: would report one gap twice.
_HISTORICAL_RESOLUTION_STATUSES = frozenset({ResolutionStatus.SUPERSEDED})

_CURRENT_RESULT = "CURRENT"


class DebtAccessDenied(Exception):
    """Raised when authorization denies debt access. Carries no investigation data."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class DebtItemNotFound(Exception):
    """Raised when a debt item is not in this reader's view of this case.

    Deliberately the same outcome whether the item does not exist at all or the
    reader may not see it. Telling those apart would confirm the existence of a
    gap in evidence they are not cleared for.
    """


@dataclass(frozen=True)
class EvidenceDebtReport:
    """A case's current debt, plus what moved since the last recorded calculation."""

    snapshot: EvidenceDebtSnapshot
    change: DebtChange


@dataclass(frozen=True)
class _Calculation:
    """One pass of detection: the snapshot and the items it was built from."""

    view: CaseDebtView
    snapshot: EvidenceDebtSnapshot
    items: tuple[EvidenceDebtItem, ...]


class EvidenceDebtService:
    def __init__(
        self,
        debt_repository: EvidenceDebtRepository,
        evidence_repository: EvidenceRepository,
        resolution_repository: ResolutionRepository,
        analytics_repository: AnalyticsRepository,
        object_store: EvidenceObjectStore,
        security: SecurityService,
        event_store: EventStore,
        policy: EvidenceDebtPolicy,
        clock: Callable[[], str] = utc_now_iso,
    ) -> None:
        self._debt = debt_repository
        self._evidence = evidence_repository
        self._resolutions = resolution_repository
        self._analytics = analytics_repository
        self._objects = object_store
        self._security = security
        self._events = event_store
        self._policy = policy
        self._clock = clock

    # -- reads ------------------------------------------------------------

    def calculate(
        self, user: User, context: AgencyContext, case: Case
    ) -> EvidenceDebtSnapshot:
        """Compute the case's debt over this reader's authorized view. Persists nothing."""
        return self._calculate(user, context, case, ACTION_VIEW_DEBT).snapshot

    def report(self, user: User, context: AgencyContext, case: Case) -> EvidenceDebtReport:
        """The current snapshot and the change since the last recorded one."""
        snapshot = self.calculate(user, context, case)
        return EvidenceDebtReport(
            snapshot=snapshot, change=self._change(snapshot, self._previous(snapshot))
        )

    def breakdown(
        self, user: User, context: AgencyContext, case: Case
    ) -> tuple[EvidenceDebtBreakdown, ...]:
        """Per-category contributions, every category reported including the empty ones."""
        return self.calculate(user, context, case).breakdown

    def list_items(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        categories: Sequence[DebtCategory] | None = None,
        statuses: Sequence[DebtStatus] | None = None,
    ) -> list[EvidenceDebtItem]:
        """Open gaps as currently detected, plus what has been recorded as resolved.

        A resolved gap leaves nothing to detect, so it is read from the record
        rather than recomputed — otherwise closing a gap would erase the fact
        that the investigation ever had it.
        """
        calculation = self._calculate(user, context, case, ACTION_VIEW_DEBT)
        items = list(calculation.items)
        live_ids = {item.debt_id for item in items}
        items.extend(
            stored
            for stored in self._debt.list_items(
                case.id,
                statuses=(DebtStatus.RESOLVED,),
                scope_fingerprint=calculation.snapshot.scope_fingerprint,
            )
            if stored.debt_id not in live_ids
        )
        return _filtered(items, categories, statuses)

    def get_item(
        self, user: User, context: AgencyContext, case: Case, debt_id: str
    ) -> EvidenceDebtItem:
        """One item, live if it is still detected and from the record if it is not."""
        for item in self.list_items(user, context, case):
            if item.debt_id == debt_id:
                return item
        raise DebtItemNotFound(debt_id)

    def item_history(
        self, user: User, context: AgencyContext, case: Case, debt_id: str
    ) -> list[EvidenceDebtItem]:
        """Every recorded version of one item. Authorized exactly as reading it is."""
        item = self.get_item(user, context, case, debt_id)
        return self._debt.list_item_history(item.debt_id, item.scope_fingerprint)

    def snapshots(
        self, user: User, context: AgencyContext, case: Case
    ) -> list[EvidenceDebtSnapshot]:
        """The recorded calculations for this reader's scope, oldest first."""
        calculation = self._calculate(user, context, case, ACTION_VIEW_DEBT)
        return self._debt.list_snapshots(
            case.id, calculation.snapshot.scope_fingerprint
        )

    # -- recalculation ----------------------------------------------------

    def recalculate(
        self, user: User, context: AgencyContext, case: Case
    ) -> EvidenceDebtReport:
        """Compute the case's debt and record it.

        Idempotent by construction: an item whose facts are unchanged is not
        rewritten, and a calculation over unchanged state produces the same
        totals, the same breakdown and the same item ids.
        """
        decision = self._authorize(user, context, case, ACTION_RECALCULATE_DEBT)
        correlation = decision.correlation_id
        self._record(
            FlightRecorderEvent.EVIDENCE_DEBT_CALCULATION_STARTED,
            user.id,
            case.id,
            correlation,
            {
                "policy_version": self._policy.policy_version,
                "debt_engine_version": DEBT_ENGINE_VERSION,
            },
        )

        try:
            view = self._build_view(user, context, case, ACTION_RECALCULATE_DEBT)
            calculation = self._compute(view, user, correlation)
        except Exception as exc:
            self._record(
                FlightRecorderEvent.EVIDENCE_DEBT_CALCULATION_FAILED,
                user.id,
                case.id,
                correlation,
                {"error_code": type(exc).__name__},
            )
            raise

        previous = self._previous(calculation.snapshot)
        for item in calculation.items:
            self._persist_item(item, user, case, correlation)
        self._resolve_absent(calculation, case, user, correlation)

        stored = self._debt.save_snapshot(replace(calculation.snapshot, persisted=True))
        change = self._change(stored, previous)
        self._record(
            FlightRecorderEvent.EVIDENCE_DEBT_CALCULATION_COMPLETED,
            user.id,
            case.id,
            correlation,
            {
                "snapshot_id": stored.snapshot_id,
                "total_debt": round(stored.total_debt, 4),
                "normalized_debt": stored.normalized_debt,
                "band": stored.band.value,
                "item_count": stored.item_count,
                "evidence_in_scope": stored.evidence_in_scope,
                "excluded_evidence_count": stored.excluded_evidence_count,
                "resolved_count": len(change.resolved_debt_ids),
                "introduced_count": len(change.introduced_debt_ids),
                "policy_version": stored.policy_version,
                "debt_engine_version": stored.debt_engine_version,
            },
        )
        return EvidenceDebtReport(snapshot=stored, change=change)

    def acknowledge_item(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        debt_id: str,
        reason: str | None = None,
    ) -> EvidenceDebtItem:
        """Record that a person has seen this gap and accepts that it stands.

        The acknowledgement survives recalculation while the item's facts are
        unchanged, so automation never quietly undoes an investigator's
        judgement. When the facts do change, the new version starts OPEN and the
        acknowledged version is kept — the history stays readable either way.
        """
        decision = self._security.authorize_action(
            user, context, ACTION_ACKNOWLEDGE_DEBT, case=case
        )
        if not decision.grants_access:
            self._record(
                FlightRecorderEvent.EVIDENCE_DEBT_ACCESS_DENIED,
                user.id,
                case.id,
                decision.correlation_id,
                {"reason": decision.reason.value, "action": ACTION_ACKNOWLEDGE_DEBT},
            )
            raise DebtAccessDenied(decision.reason.value)

        item = self.get_item(user, context, case, debt_id)
        if item.status is not DebtStatus.OPEN:
            return item
        if self._debt.get_item(item.debt_id, item.scope_fingerprint) is None:
            # Acknowledging a gap that has never been recorded records it first,
            # so the person's action has something durable to attach to.
            self._debt.save_item(item)

        updated = self._debt.update_item_status(
            debt_id=item.debt_id,
            scope_fingerprint=item.scope_fingerprint,
            status=DebtStatus.ACKNOWLEDGED,
            changed_at=self._clock(),
            changed_by=user.id,
            reason=reason,
        )
        self._record(
            FlightRecorderEvent.EVIDENCE_DEBT_REVISED,
            user.id,
            case.id,
            decision.correlation_id,
            {
                "debt_id": updated.debt_id,
                "category": updated.category.value,
                "status": updated.status.value,
                "version": updated.version,
                "policy_version": updated.policy_version,
                "debt_engine_version": updated.debt_engine_version,
            },
        )
        return updated

    # -- calculation ------------------------------------------------------

    def _calculate(
        self, user: User, context: AgencyContext, case: Case, action: str
    ) -> _Calculation:
        decision = self._authorize(user, context, case, action)
        view = self._build_view(user, context, case, action)
        return self._compute(view, user, decision.correlation_id)

    def _compute(
        self, view: CaseDebtView, user: User, correlation: str
    ) -> _Calculation:
        """Detect, weigh, rank and summarise. One pass, no storage written."""
        calculated_at = self._clock()
        fingerprint = scope_fingerprint(view.evidence_ids)
        items = self._items(view, fingerprint, calculated_at)
        total = round(sum(item.contribution for item in items), 6)
        normalized = self._policy.normalize(total)
        snapshot = EvidenceDebtSnapshot(
            snapshot_id=snapshot_identity(
                view.case_id, fingerprint, calculated_at, self._policy.policy_version
            ),
            case_id=view.case_id,
            calculated_at=calculated_at,
            calculated_by=user.id,
            correlation_id=correlation,
            total_debt=total,
            normalized_debt=normalized,
            band=self._policy.band_for(normalized),
            item_count=len(items),
            breakdown=build_breakdown(items),
            top_items=tuple(items[: self._policy.limits.top_items]),
            debt_ids=tuple(sorted(item.debt_id for item in items)),
            evidence_in_scope=len(view.evidence_ids),
            excluded_evidence_count=view.excluded_evidence_count,
            scope_fingerprint=fingerprint,
            policy_version=self._policy.policy_version,
            debt_engine_version=DEBT_ENGINE_VERSION,
        )
        return _Calculation(view=view, snapshot=snapshot, items=tuple(items))

    def _items(
        self, view: CaseDebtView, fingerprint: str, calculated_at: str
    ) -> list[EvidenceDebtItem]:
        """Detected findings, weighted, ranked and merged with persisted lifecycle."""
        weighed = [
            (finding, self._weigh(finding), self._identity(view.case_id, finding))
            for finding in detectors.detect(view, self._policy)
        ]
        ranked = sorted(weighed, key=lambda entry: (-entry[1].weighted_contribution, entry[2]))
        return [
            self._merge_lifecycle(
                self._item(finding, weighting, debt_id, view, fingerprint, priority, calculated_at)
            )
            for priority, (finding, weighting, debt_id) in enumerate(ranked, start=1)
        ]

    def _item(
        self,
        finding: DebtFinding,
        weighting: DebtWeighting,
        debt_id: str,
        view: CaseDebtView,
        fingerprint: str,
        priority: int,
        calculated_at: str,
    ) -> EvidenceDebtItem:
        category = self._policy.category(finding.category)
        return EvidenceDebtItem(
            debt_id=debt_id,
            case_id=view.case_id,
            category=finding.category,
            severity=finding.severity,
            status=DebtStatus.OPEN,
            reason=finding.reason,
            subject=finding.subject,
            weighting=weighting,
            explanation=dict(finding.explanation),
            supporting_evidence_ids=tuple(sorted(finding.supporting_evidence_ids)),
            related_resolution_ids=tuple(sorted(finding.related_resolution_ids)),
            related_finding_ids=tuple(sorted(finding.related_finding_ids)),
            created_at=calculated_at,
            calculated_at=calculated_at,
            policy_version=self._policy.policy_version,
            debt_engine_version=DEBT_ENGINE_VERSION,
            actionable=category.actionable,
            priority=priority,
            blocking_reason=finding.blocking_reason,
            required_capability=category.required_capability,
            scope_fingerprint=fingerprint,
            fact_fingerprint=fact_fingerprint(
                finding.category,
                finding.severity,
                finding.reason,
                finding.subject,
                weighting,
                finding.supporting_evidence_ids,
                self._policy.policy_version,
                DEBT_ENGINE_VERSION,
            ),
        )

    def _weigh(self, finding: DebtFinding) -> DebtWeighting:
        """Four named factors and their product. No step is hidden from the record."""
        category = self._policy.category(finding.category)
        severity = self._policy.severity_multiplier(finding.severity)
        scope = self._policy.scope.factor(finding.affected_scope)
        criticality = self._policy.criticality.factor(finding.critical)
        return DebtWeighting(
            category_weight=category.weight,
            severity_multiplier=severity,
            scope_factor=scope,
            criticality_factor=criticality,
            affected_scope=finding.affected_scope,
            weighted_contribution=round(category.weight * severity * scope * criticality, 6),
        )

    def _identity(self, case_id: str, finding: DebtFinding) -> str:
        return debt_identity(
            case_id,
            finding.category,
            finding.subject.subject_type,
            finding.subject.reference,
            *finding.discriminators,
        )

    def _merge_lifecycle(self, item: EvidenceDebtItem) -> EvidenceDebtItem:
        """Carry an investigator's acknowledgement and the item's age forward."""
        stored = self._debt.get_item(item.debt_id, item.scope_fingerprint)
        if stored is None:
            return item
        acknowledged = (
            stored.status is DebtStatus.ACKNOWLEDGED
            and stored.fact_fingerprint == item.fact_fingerprint
        )
        return replace(
            item,
            created_at=stored.created_at,
            version=stored.version,
            status=DebtStatus.ACKNOWLEDGED if acknowledged else DebtStatus.OPEN,
            status_changed_at=stored.status_changed_at if acknowledged else None,
            status_changed_by=stored.status_changed_by if acknowledged else None,
            status_reason=stored.status_reason if acknowledged else None,
        )

    # -- persistence ------------------------------------------------------

    def _persist_item(
        self, item: EvidenceDebtItem, user: User, case: Case, correlation: str
    ) -> None:
        existing = self._debt.get_item(item.debt_id, item.scope_fingerprint)
        if existing is not None and existing.fact_fingerprint == item.fact_fingerprint:
            return  # unchanged facts: recalculation manufactures nothing
        stored = self._debt.save_item(item)
        self._record(
            FlightRecorderEvent.EVIDENCE_DEBT_REVISED
            if existing is not None
            else FlightRecorderEvent.EVIDENCE_DEBT_CREATED,
            user.id,
            case.id,
            correlation,
            {
                "debt_id": stored.debt_id,
                "category": stored.category.value,
                "severity": stored.severity.value,
                "reason": stored.reason.value,
                "status": stored.status.value,
                "version": stored.version,
                "weighted_contribution": round(stored.contribution, 4),
                "subject_type": stored.subject.subject_type.value,
                "policy_version": stored.policy_version,
                "debt_engine_version": stored.debt_engine_version,
            },
        )

    def _resolve_absent(
        self, calculation: _Calculation, case: Case, user: User, correlation: str
    ) -> None:
        """Close records for gaps this calculation no longer finds.

        Scoped to the records this calculation could itself have produced, so a
        reader never closes a gap they cannot see — and a gap that exists only
        in a wider scope is left exactly as it was.
        """
        detected = {item.debt_id for item in calculation.items}
        fingerprint = calculation.snapshot.scope_fingerprint
        now = self._clock()
        for stored in self._debt.list_items(
            case.id,
            statuses=(DebtStatus.OPEN, DebtStatus.ACKNOWLEDGED),
            scope_fingerprint=fingerprint,
        ):
            if stored.debt_id in detected:
                continue
            closed = self._debt.update_item_status(
                debt_id=stored.debt_id,
                scope_fingerprint=fingerprint,
                status=DebtStatus.RESOLVED,
                changed_at=now,
                changed_by=user.id,
                reason="NO_LONGER_DETECTED",
            )
            self._record(
                FlightRecorderEvent.EVIDENCE_DEBT_RESOLVED,
                user.id,
                case.id,
                correlation,
                {
                    "debt_id": closed.debt_id,
                    "category": closed.category.value,
                    "previous_status": stored.status.value,
                    "version": closed.version,
                    "reason": "NO_LONGER_DETECTED",
                },
            )

    def _previous(self, snapshot: EvidenceDebtSnapshot) -> EvidenceDebtSnapshot | None:
        """The last recorded snapshot for the same scope, never for a wider one."""
        return self._debt.latest_snapshot(snapshot.case_id, snapshot.scope_fingerprint)

    def _change(
        self, snapshot: EvidenceDebtSnapshot, previous: EvidenceDebtSnapshot | None
    ) -> DebtChange:
        if previous is None:
            return DebtChange(
                previous_snapshot_id=None,
                previous_total=0.0,
                delta=round(snapshot.total_debt, 6),
                resolved_debt_ids=(),
                introduced_debt_ids=snapshot.debt_ids,
                unchanged_count=0,
            )
        current_ids = set(snapshot.debt_ids)
        previous_ids = set(previous.debt_ids)
        return DebtChange(
            previous_snapshot_id=previous.snapshot_id,
            previous_total=round(previous.total_debt, 6),
            delta=round(snapshot.total_debt - previous.total_debt, 6),
            resolved_debt_ids=tuple(sorted(previous_ids - current_ids)),
            introduced_debt_ids=tuple(sorted(current_ids - previous_ids)),
            unchanged_count=len(current_ids & previous_ids),
        )

    # -- authorized view --------------------------------------------------

    def _build_view(
        self, user: User, context: AgencyContext, case: Case, action: str
    ) -> CaseDebtView:
        """Assemble everything debt may see, and nothing it may not.

        Authorization happens per evidence item and *before* any state is read,
        so denied evidence never contributes an item, a count or a fraction of a
        total. Resolutions and findings inherit that scope: a resolution needs
        both its evidence items authorized, and a finding needs every evidence
        item it cites.
        """
        authorized: list[DebtEvidenceView] = []
        redacted: set[str] = set()
        excluded = 0
        for record in self._evidence.list_evidence_for_case(case.id):
            decision = self._security.authorize_evidence_access(
                user, context, case, record, action
            )
            if not decision.grants_access:
                excluded += 1
                continue
            redacted.update(decision.redacted_fields)
            authorized.append(self._evidence_view(record))

        allowed = {item.evidence_id for item in authorized}
        return CaseDebtView(
            case_id=case.id,
            evidence=tuple(sorted(authorized, key=lambda item: item.evidence_id)),
            resolutions=self._resolution_views(case, allowed),
            signals=self._signal_views(case, allowed),
            evidence_ids=tuple(sorted(allowed)),
            excluded_evidence_count=excluded,
            masked_fields=tuple(sorted(redacted)),
        )

    def _evidence_view(self, record: EvidenceRecord) -> DebtEvidenceView:
        versions = self._evidence.list_versions(record.id)
        latest = versions[-1] if versions else None
        return DebtEvidenceView(
            evidence_id=record.id,
            source_id=record.source_id,
            classification=record.classification.value,
            state=record.state.value,
            latest_version_id=None if latest is None else latest.version_id,
            version_count=len(versions),
            results=tuple(
                self._result_view(result) for result in self._evidence.list_results(record.id)
            ),
        )

    def _result_view(self, result: AnalysisResult) -> DebtResultView:
        return DebtResultView(
            result_id=result.result_id,
            task_type=result.task_type,
            state=result.state.value,
            evidence_version_id=result.evidence_version_id,
            created_at=result.created_at,
            conflict_metrics=self._conflict_metrics(result),
        )

    def _conflict_metrics(self, result: AnalysisResult) -> dict[str, int]:
        """The disagreement counts an analyzer already reported, and only those.

        Named by policy and read as integers. The debt engine does not open a
        result to look around in it: a field the policy does not name is never
        read, so a value it has no business seeing cannot reach a debt item.
        """
        wanted = {
            rule.metric
            for rule in self._policy.result_conflicts
            if rule.task_type == result.task_type
        }
        if not wanted or result.payload_ref is None or result.state.value != _CURRENT_RESULT:
            return {}
        try:
            payload = json.loads(self._objects.get(result.payload_ref))
        except Exception:
            # A result whose payload cannot be read is not evidence of a
            # conflict. Staleness and missing-analysis debt still describe it.
            return {}
        if not isinstance(payload, Mapping):
            return {}
        metrics: dict[str, int] = {}
        for metric in sorted(wanted):
            value = payload.get(metric)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            metrics[metric] = int(value)
        return metrics

    def _resolution_views(
        self, case: Case, allowed: set[str]
    ) -> tuple[DebtResolutionView, ...]:
        views = []
        for decision in self._resolutions.list_decisions(case.id):
            if decision.status in _HISTORICAL_RESOLUTION_STATUSES:
                continue
            if (
                decision.left.evidence_id not in allowed
                or decision.right.evidence_id not in allowed
            ):
                # Exactly the rule entity resolution applies: a decision derived
                # from two evidence items is readable only when both are.
                continue
            views.append(
                DebtResolutionView(
                    resolution_id=decision.resolution_id,
                    lineage_id=decision.lineage_id,
                    status=decision.status.value,
                    recommendation=decision.score.recommendation.value,
                    left_evidence_id=decision.left.evidence_id,
                    right_evidence_id=decision.right.evidence_id,
                    left_entity_ref=decision.left.entity_ref,
                    right_entity_ref=decision.right.entity_ref,
                    score=decision.score.score,
                    evidence_weight=decision.score.evidence_weight,
                    conflicts=tuple(
                        DebtConflictView(
                            attribute=conflict.attribute,
                            rule=conflict.rule,
                            penalty=conflict.penalty,
                            blocks_auto_accept=conflict.blocks_auto_accept,
                        )
                        for conflict in decision.score.conflicts
                    ),
                    review_actions=tuple(
                        review.action.value
                        for review in self._resolutions.list_reviews(decision.resolution_id)
                    ),
                )
            )
        return tuple(sorted(views, key=lambda view: view.lineage_id))

    def _signal_views(self, case: Case, allowed: set[str]) -> tuple[DebtSignalView, ...]:
        views = []
        for signal in self._analytics.list_signals(case.id):
            if not set(signal.supporting_evidence_ids) <= allowed:
                # A finding computed partly from evidence this reader may not
                # see would disclose that the evidence exists.
                continue
            views.append(
                DebtSignalView(
                    signal_id=signal.signal_id,
                    signal_type=signal.signal_type.value,
                    score=signal.score,
                    reasons=tuple(reason.value for reason in signal.reasons),
                    supporting_evidence_ids=tuple(sorted(signal.supporting_evidence_ids)),
                    entity_refs=tuple(sorted(signal.entity_ids)),
                )
            )
        return tuple(sorted(views, key=lambda view: view.signal_id))

    # -- authorization ----------------------------------------------------

    def _authorize(
        self, user: User, context: AgencyContext, case: Case, action: str
    ) -> AuthorizationDecision:
        decision = self._security.authorize_case_access(user, context, case, action)
        if not decision.grants_access:
            self._record(
                FlightRecorderEvent.EVIDENCE_DEBT_ACCESS_DENIED,
                user.id,
                case.id,
                decision.correlation_id,
                {"reason": decision.reason.value, "scope": "CASE", "action": action},
            )
            raise DebtAccessDenied(decision.reason.value)
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


def _filtered(
    items: Iterable[EvidenceDebtItem],
    categories: Sequence[DebtCategory] | None,
    statuses: Sequence[DebtStatus] | None,
) -> list[EvidenceDebtItem]:
    selected = list(items)
    if categories:
        wanted = set(categories)
        selected = [item for item in selected if item.category in wanted]
    if statuses:
        allowed = set(statuses)
        selected = [item for item in selected if item.status in allowed]
    return sorted(selected, key=lambda item: (-item.contribution, item.debt_id))
