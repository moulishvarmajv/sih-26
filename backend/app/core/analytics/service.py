"""Graph analytics application service.

The only path between the API and the analytics layer, and the place this
phase's security property is established:

    raw graph -> case scope -> evidence authorization -> privacy -> view -> signal

Analytics never reaches the graph repository for structural work. It asks
GraphService for the authorized, masked graph a *particular reader* is allowed
to see, and computes from that alone. A reader who may not see an evidence item
does not get signals computed from it and then filtered out — those observations
were never in scope, so the entities they would have introduced do not exist as
far as the metrics are concerned.

Two consequences worth stating plainly, because they look like defects
otherwise:

- **Two readers can legitimately get different answers.** Degree is degree
  *within the authorized graph*. A narrower reader sees a smaller graph, and its
  ranks are that graph's ranks.
- **A read computes but never persists.** The overview, entity and path
  operations are queries over the authorized view; they create no run and no
  signal. Persisting signals is an explicit run, for the same reason that
  viewing evidence never starts a processing run.

Path finding is the one analytic pushed down to the database, because the
database can answer it without anyone loading the graph. Everything structural
is computed here, over one view, so two metrics can never disagree about the
graph they described.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from app.core.analytics.graph_view import AnalysableGraph, build_view
from app.core.analytics.metrics import bridges as compute_bridges
from app.core.analytics.metrics import components as compute_components
from app.core.analytics.metrics import concentrated_windows
from app.core.analytics.metrics import connectivity as compute_connectivity
from app.core.analytics.models import (
    AnalyticsEntity,
    AnalyticsRun,
    BridgeMetric,
    ConnectivityMetric,
    EntityPath,
    GraphComponent,
    InvestigationSignal,
    PathStep,
    SignalMetric,
    SignalReason,
    SignalType,
    TemporalWindow,
    run_identity,
    signal_identity,
)
from app.core.analytics.policy import AnalyticsPolicy
from app.core.analytics.repository import AnalyticsRepository
from app.core.audit.event_store import ActorType, EventDraft, EventStore, FlightRecorderEvent
from app.core.domain.agency import AgencyContext
from app.core.domain.case import Case
from app.core.domain.identity import User
from app.core.graph.models import GraphPath
from app.core.graph.repository import GraphRepository
from app.core.graph.service import GraphAccessDenied, GraphService
from app.infrastructure.clock import utc_now_iso

ACTION_VIEW_ANALYTICS = "VIEW_ANALYTICS"
ACTION_RUN_ANALYTICS = "RUN_ANALYTICS"


class AnalyticsAccessDenied(Exception):
    """Raised when authorization denies analytics. Carries no graph data."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AnalyticsEntityNotFound(Exception):
    """Raised when an entity is not in the reader's authorized graph.

    Deliberately the same outcome whether the entity does not exist at all or
    the reader may not see it. Telling those apart would confirm the existence
    of something outside their scope.
    """


class SignalNotFound(Exception):
    """Raised when a signal does not exist in the case being asked about."""


@dataclass(frozen=True)
class AnalyticsOverview:
    """A read-model of the case's shape, computed live and persisted nowhere."""

    case_id: str
    analytics_version: str
    entity_count: int
    relationship_count: int
    evidence_in_scope: int
    excluded_evidence_count: int
    truncated: bool
    masked_properties: tuple[str, ...]
    components: tuple[GraphComponent, ...]
    top_connectivity: tuple[ConnectivityMetric, ...]
    bridges: tuple[BridgeMetric, ...]
    concentrations: tuple[TemporalWindow, ...]


@dataclass(frozen=True)
class EntityAnalytics:
    """Everything the authorized graph says about the shape around one entity."""

    case_id: str
    analytics_version: str
    entity: AnalyticsEntity
    connectivity: ConnectivityMetric
    bridge: BridgeMetric | None
    component_id: str | None
    component_entity_count: int
    neighbours: tuple[AnalyticsEntity, ...]
    masked_properties: tuple[str, ...]


class GraphAnalyticsService:
    def __init__(
        self,
        graph_service: GraphService,
        graph_repository: GraphRepository,
        analytics_repository: AnalyticsRepository,
        event_store: EventStore,
        policy: AnalyticsPolicy,
        clock: Callable[[], str] = utc_now_iso,
    ) -> None:
        self._graphs = graph_service
        self._repository = graph_repository
        self._analytics = analytics_repository
        self._events = event_store
        self._policy = policy
        self._clock = clock

    # -- reads ------------------------------------------------------------

    def overview(self, user: User, context: AgencyContext, case: Case) -> AnalyticsOverview:
        """Compute the case's structure. Persists nothing."""
        graph, _ = self._view(user, context, case, ACTION_VIEW_ANALYTICS)
        connectivity = compute_connectivity(graph, self._policy)
        return AnalyticsOverview(
            case_id=case.id,
            analytics_version=self._policy.analytics_version,
            entity_count=graph.entity_count,
            relationship_count=graph.relationship_count,
            evidence_in_scope=len(graph.evidence_ids),
            excluded_evidence_count=graph.excluded_evidence_count,
            truncated=graph.truncated,
            masked_properties=graph.masked_properties,
            components=tuple(compute_components(graph, self._policy)),
            top_connectivity=tuple(connectivity[: self._policy.connectivity.top_n]),
            bridges=tuple(compute_bridges(graph, self._policy)),
            concentrations=tuple(concentrated_windows(graph, self._policy)),
        )

    def entity_analytics(
        self, user: User, context: AgencyContext, case: Case, entity_id: str
    ) -> EntityAnalytics:
        graph, _ = self._view(user, context, case, ACTION_VIEW_ANALYTICS)
        entity = graph.entity(entity_id)
        if entity is None:
            raise AnalyticsEntityNotFound(entity_id)

        connectivity = compute_connectivity(graph, self._policy)
        measured = next(
            metric for metric in connectivity if metric.entity.entity_id == entity_id
        )
        bridge = next(
            (
                metric
                for metric in compute_bridges(graph, self._policy)
                if metric.entity.entity_id == entity_id
            ),
            None,
        )
        component = next(
            (
                group
                for group in compute_components(graph, self._policy)
                if any(member.entity_id == entity_id for member in group.members)
            ),
            None,
        )
        return EntityAnalytics(
            case_id=case.id,
            analytics_version=self._policy.analytics_version,
            entity=entity,
            connectivity=measured,
            bridge=bridge,
            component_id=None if component is None else component.component_id,
            component_entity_count=0 if component is None else component.entity_count,
            neighbours=tuple(
                graph.entities[neighbour]
                for neighbour in sorted(graph.neighbours(entity_id))
                if neighbour in graph.entities
            ),
            masked_properties=graph.masked_properties,
        )

    def shortest_path(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        source_id: str,
        target_id: str,
    ) -> EntityPath:
        """Shortest observed walk between two authorized entities.

        Both endpoints must already be visible to this reader. The hashed entity
        id is resolved back to a natural key only here, from the authorized
        view, so a caller cannot ask about an entity they cannot see: there is
        nothing to resolve the id against.
        """
        graph, authorized = self._view(user, context, case, ACTION_VIEW_ANALYTICS)
        keys = {node.id: node.key for node in authorized.nodes}
        source, target = graph.entity(source_id), graph.entity(target_id)
        if source is None or target is None:
            raise AnalyticsEntityNotFound(source_id if source is None else target_id)

        max_length = self._policy.limits.max_path_length
        found: GraphPath | None = self._repository.find_shortest_path(
            case_id=case.id,
            start_key=keys[source_id],
            end_key=keys[target_id],
            evidence_ids=list(graph.evidence_ids),
            max_length=max_length,
        )
        path = self._to_entity_path(case, graph, source, target, found, max_length)
        self._record(
            FlightRecorderEvent.ANALYTICS_COMPLETED,
            user.id,
            case.id,
            "-",
            {
                "operation": "SHORTEST_PATH",
                "analytics_version": self._policy.analytics_version,
                "found": path.found,
                "length": path.length,
                "max_length": max_length,
            },
        )
        return path

    def list_signals(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        signal_types: Sequence[SignalType] | None = None,
    ) -> list[InvestigationSignal]:
        """Read persisted signals. Never computes any."""
        self._authorize(user, context, case, ACTION_VIEW_ANALYTICS)
        return self._analytics.list_signals(case.id, signal_types)

    def get_signal(
        self, user: User, context: AgencyContext, case: Case, signal_id: str
    ) -> InvestigationSignal:
        self._authorize(user, context, case, ACTION_VIEW_ANALYTICS)
        signal = self._analytics.get_signal(signal_id)
        if signal is None or signal.case_id != case.id:
            raise SignalNotFound(signal_id)
        return signal

    # -- run --------------------------------------------------------------

    def run(self, user: User, context: AgencyContext, case: Case) -> AnalyticsRun:
        """Compute signals over the authorized graph and persist them."""
        decision = self._authorize(user, context, case, ACTION_RUN_ANALYTICS)
        correlation = decision.correlation_id
        self._record(
            FlightRecorderEvent.ANALYTICS_STARTED,
            user.id,
            case.id,
            correlation,
            {"analytics_version": self._policy.analytics_version},
        )

        try:
            graph, _ = self._view(user, context, case, ACTION_RUN_ANALYTICS)
            executed_at = self._clock()
            run_id = run_identity(
                case.id,
                self._policy.analytics_version,
                executed_at,
                ",".join(graph.evidence_ids),
            )
            signals = self._build_signals(graph, case, run_id, executed_at)
        except AnalyticsAccessDenied:
            raise
        except Exception as exc:
            self._record(
                FlightRecorderEvent.ANALYTICS_FAILED,
                user.id,
                case.id,
                correlation,
                {"error_code": type(exc).__name__},
            )
            raise

        for signal in signals:
            previous = self._analytics.get_signal(signal.signal_id)
            stored = self._analytics.save_signal(signal)
            self._record(
                FlightRecorderEvent.SIGNAL_REVISED
                if previous is not None
                else FlightRecorderEvent.SIGNAL_CREATED,
                user.id,
                case.id,
                correlation,
                {
                    "signal_id": stored.signal_id,
                    "signal_type": stored.signal_type.value,
                    "version": stored.version,
                    "score": round(stored.score, 4),
                    "confidence": stored.confidence,
                    "reasons": [reason.value for reason in stored.reasons],
                    "analytics_version": stored.analytics_version,
                },
            )

        run = self._analytics.save_run(
            AnalyticsRun(
                run_id=run_id,
                case_id=case.id,
                analytics_version=self._policy.analytics_version,
                executed_at=executed_at,
                executed_by=user.id,
                correlation_id=correlation,
                evidence_ids=graph.evidence_ids,
                node_count=graph.entity_count,
                relationship_count=graph.relationship_count,
                signal_count=len(signals),
                excluded_evidence_count=graph.excluded_evidence_count,
                truncated=graph.truncated,
            )
        )
        self._record(
            FlightRecorderEvent.ANALYTICS_COMPLETED,
            user.id,
            case.id,
            correlation,
            {
                "operation": "RUN",
                "run_id": run.run_id,
                "analytics_version": run.analytics_version,
                "signal_count": run.signal_count,
                "node_count": run.node_count,
                "relationship_count": run.relationship_count,
                "excluded_evidence_count": run.excluded_evidence_count,
                "truncated": run.truncated,
            },
        )
        return run

    # -- signal construction ----------------------------------------------

    def _build_signals(
        self, graph: AnalysableGraph, case: Case, run_id: str, created_at: str
    ) -> list[InvestigationSignal]:
        signals: list[InvestigationSignal] = []
        limit = self._policy.limits.max_signals_per_type

        connectivity = compute_connectivity(graph, self._policy)
        for metric in connectivity[: self._policy.connectivity.top_n][:limit]:
            if metric.degree < self._policy.connectivity.minimum_degree:
                continue
            signals.append(self._connectivity_signal(metric, case, run_id, created_at))

        for metric in compute_bridges(graph, self._policy)[:limit]:
            signals.append(self._bridge_signal(metric, case, run_id, created_at))

        for component in compute_components(graph, self._policy)[:limit]:
            signals.append(self._component_signal(component, case, run_id, created_at))

        for window in concentrated_windows(graph, self._policy)[:limit]:
            signals.append(self._temporal_signal(window, case, run_id, created_at))

        return signals

    def _connectivity_signal(
        self, metric: ConnectivityMetric, case: Case, run_id: str, created_at: str
    ) -> InvestigationSignal:
        """High connectivity within the case graph. Not a statement about conduct.

        A busy number is usually a busy number — a helpdesk, a dispatcher, a
        shared handset. The signal says where the graph is dense and leaves the
        meaning to whoever reads the evidence.
        """
        policy = self._policy.connectivity
        metrics = (
            self._metric("degree", metric.degree, policy, "degree", "degree_saturates_at"),
            self._metric(
                "distinct_neighbours",
                metric.distinct_neighbours,
                policy,
                "distinct_neighbours",
                "distinct_neighbours_saturates_at",
            ),
            self._metric(
                "entity_types_touched",
                len(metric.entity_types_touched),
                policy,
                "entity_types_touched",
                "entity_types_saturates_at",
            ),
        )
        reasons = [SignalReason.DEGREE_ABOVE_THRESHOLD]
        if metric.rank == 1:
            reasons.append(SignalReason.TOP_RANKED_CONNECTIVITY)
        return self._signal(
            case=case,
            signal_type=SignalType.HIGH_CONNECTIVITY,
            entities=(metric.entity,),
            metrics=metrics,
            reasons=tuple(reasons),
            relationship_ids=metric.supporting_relationship_ids,
            evidence_ids=metric.supporting_evidence_ids,
            run_id=run_id,
            created_at=created_at,
            detail={
                "degree": metric.degree,
                "in_degree": metric.in_degree,
                "out_degree": metric.out_degree,
                "distinct_neighbours": metric.distinct_neighbours,
                "entity_types_touched": list(metric.entity_types_touched),
                "rank": metric.rank,
                "rank_of": metric.rank_of,
                "minimum_degree": policy.minimum_degree,
            },
        )

    def _bridge_signal(
        self, metric: BridgeMetric, case: Case, run_id: str, created_at: str
    ) -> InvestigationSignal:
        policy = self._policy.bridge
        metrics = (
            self._metric(
                "groups_separated",
                metric.groups_separated,
                policy,
                "groups_separated",
                "groups_saturates_at",
            ),
            self._metric(
                "separated_side_size",
                metric.separated_side_size,
                policy,
                "separated_side_size",
                "separated_side_saturates_at",
            ),
            self._metric(
                "entity_types_spanned",
                len(metric.entity_types_spanned),
                policy,
                "entity_types_spanned",
                "entity_types_saturates_at",
            ),
            self._metric(
                "neighbour_spread",
                metric.neighbour_count,
                policy,
                "neighbour_spread",
                "neighbours_saturates_at",
            ),
        )
        reasons = [
            SignalReason.REMOVAL_SEPARATES_GRAPH,
            SignalReason.CONNECTS_SEPARATE_GROUPS,
        ]
        if len(metric.entity_types_spanned) >= policy.minimum_entity_types:
            reasons.append(SignalReason.SPANS_MULTIPLE_ENTITY_TYPES)
        if metric.rests_on_weak_relationship:
            reasons.append(SignalReason.RESTS_ON_SINGLE_WEAK_RELATIONSHIP)
        return self._signal(
            case=case,
            signal_type=SignalType.CROSS_DOMAIN_BRIDGE,
            entities=(metric.entity,),
            metrics=metrics,
            reasons=tuple(reasons),
            relationship_ids=metric.supporting_relationship_ids,
            evidence_ids=metric.supporting_evidence_ids,
            run_id=run_id,
            created_at=created_at,
            detail={
                "groups_separated": metric.groups_separated,
                "group_sizes": list(metric.group_sizes),
                "separated_side_size": metric.separated_side_size,
                "entity_types_spanned": list(metric.entity_types_spanned),
                "neighbour_count": metric.neighbour_count,
                "rests_on_weak_relationship": metric.rests_on_weak_relationship,
                "weak_relationship_seconds": policy.weak_relationship_duration_seconds,
            },
        )

    def _component_signal(
        self, component: GraphComponent, case: Case, run_id: str, created_at: str
    ) -> InvestigationSignal:
        """Structure only: how the case graph divides into groups."""
        isolated = component.entity_count <= self._policy.components.isolated_maximum_members
        reasons = [SignalReason.CONNECTS_SEPARATE_GROUPS]
        if isolated:
            reasons = [SignalReason.COMPONENT_IS_ISOLATED]
        return self._signal(
            case=case,
            signal_type=SignalType.COMPONENT_STRUCTURE,
            entities=component.members,
            metrics=(),
            reasons=tuple(reasons),
            relationship_ids=(),
            evidence_ids=component.supporting_evidence_ids,
            run_id=run_id,
            created_at=created_at,
            identity_subjects=(component.component_id,),
            detail={
                "component_id": component.component_id,
                "entity_count": component.entity_count,
                "relationship_count": component.relationship_count,
                "entity_type_counts": dict(component.entity_type_counts),
                "dominant_entity_type": component.dominant_entity_type,
                "isolated": isolated,
            },
        )

    def _temporal_signal(
        self, window: TemporalWindow, case: Case, run_id: str, created_at: str
    ) -> InvestigationSignal:
        policy = self._policy.temporal
        metrics = (
            self._metric(
                "concentration_ratio",
                window.concentration_ratio,
                policy,
                "concentration_ratio",
                "ratio_saturates_at",
            ),
            self._metric(
                "event_count", window.event_count, policy, "event_count", "events_saturate_at"
            ),
        )
        return self._signal(
            case=case,
            signal_type=SignalType.TEMPORAL_CONCENTRATION,
            entities=(),
            metrics=metrics,
            reasons=(SignalReason.EVENTS_CONCENTRATED_IN_WINDOW,),
            relationship_ids=window.supporting_relationship_ids,
            evidence_ids=window.supporting_evidence_ids,
            run_id=run_id,
            created_at=created_at,
            identity_subjects=(window.window_start,),
            detail={
                "window_start": window.window_start,
                "window_end": window.window_end,
                "window_seconds": policy.window_seconds,
                "event_count": window.event_count,
                "mean_event_count": window.mean_event_count,
                "concentration_ratio": window.concentration_ratio,
                "minimum_events_in_window": policy.minimum_events_in_window,
                "concentration_multiple": policy.concentration_multiple,
            },
        )

    def _metric(
        self, name: str, value: float, policy: Any, weight_key: str, saturation_key: str
    ) -> SignalMetric:
        """One weighted input, with the normalization that produced it on show."""
        weight = float(policy.weights.get(weight_key, 0.0))
        saturation = float(policy.normalization.get(saturation_key, 0.0))
        normalized = 0.0 if saturation <= 0 else min(1.0, max(0.0, value / saturation))
        return SignalMetric(
            name=name,
            value=float(value),
            normalized=round(normalized, 6),
            weight=weight,
            contribution=round(normalized * weight, 6),
        )

    def _signal(
        self,
        case: Case,
        signal_type: SignalType,
        entities: Sequence[AnalyticsEntity],
        metrics: Sequence[SignalMetric],
        reasons: Sequence[SignalReason],
        relationship_ids: Sequence[str],
        evidence_ids: Sequence[str],
        run_id: str,
        created_at: str,
        detail: Mapping[str, Any],
        identity_subjects: Sequence[str] | None = None,
    ) -> InvestigationSignal:
        score = round(min(1.0, sum(metric.contribution for metric in metrics)), 6)
        subjects = (
            list(identity_subjects)
            if identity_subjects is not None
            else [entity.entity_id for entity in entities]
        )
        return InvestigationSignal(
            signal_id=signal_identity(case.id, signal_type, *subjects),
            case_id=case.id,
            signal_type=signal_type,
            entities=tuple(entities),
            score=score,
            confidence=self._policy.band_for(score).band,
            reasons=tuple(reasons),
            metrics=tuple(metrics),
            supporting_relationship_ids=tuple(relationship_ids),
            supporting_evidence_ids=tuple(evidence_ids),
            created_at=created_at,
            analytics_version=self._policy.analytics_version,
            run_id=run_id,
            detail=dict(detail),
        )

    # -- authorization ----------------------------------------------------

    def _authorize(self, user: User, context: AgencyContext, case: Case, action: str):
        try:
            return self._graphs.authorize_case(user, context, case, action)
        except GraphAccessDenied as denied:
            self._record(
                FlightRecorderEvent.ANALYTICS_ACCESS_DENIED,
                user.id,
                case.id,
                "-",
                {"reason": denied.reason, "action": action},
            )
            raise AnalyticsAccessDenied(denied.reason) from None

    def _view(self, user: User, context: AgencyContext, case: Case, action: str):
        """The authorized, masked graph, reduced to the analysable view."""
        try:
            authorized = self._graphs.get_case_graph(user, context, case, action=action)
        except GraphAccessDenied as denied:
            self._record(
                FlightRecorderEvent.ANALYTICS_ACCESS_DENIED,
                user.id,
                case.id,
                "-",
                {"reason": denied.reason, "action": action},
            )
            raise AnalyticsAccessDenied(denied.reason) from None
        view = build_view(
            authorized,
            self._policy.limits.max_relationships,
            authorized.evidence_ids,
        )
        return view, authorized

    # -- helpers ----------------------------------------------------------

    def _to_entity_path(
        self,
        case: Case,
        graph: AnalysableGraph,
        source: AnalyticsEntity,
        target: AnalyticsEntity,
        found: GraphPath | None,
        max_length: int,
    ) -> EntityPath:
        """Rebuild a repository path using only entities the reader may see.

        Every node on the path is looked up in the authorized view rather than
        read from the row the database returned. A node that is not in the view
        means the path left the reader's scope, and the answer becomes "no path"
        — the walk is not reported with a hole in it.
        """
        if found is None or not found.relationships:
            return EntityPath(
                case_id=case.id,
                source=source,
                target=target,
                steps=(),
                length=0,
                found=False,
                max_length_searched=max_length,
                reason=SignalReason.NO_PATH_WITHIN_LIMIT,
                analytics_version=self._policy.analytics_version,
            )

        steps: list[PathStep] = []
        for relationship in found.relationships:
            start = graph.entity(relationship.start.id)
            end = graph.entity(relationship.end.id)
            if start is None or end is None:
                return EntityPath(
                    case_id=case.id,
                    source=source,
                    target=target,
                    steps=(),
                    length=0,
                    found=False,
                    max_length_searched=max_length,
                    reason=SignalReason.NO_PATH_WITHIN_LIMIT,
                    analytics_version=self._policy.analytics_version,
                )
            provenance = relationship.provenance
            steps.append(
                PathStep(
                    relationship_id=relationship.observation_id,
                    relationship_type=relationship.type.value,
                    from_entity=start,
                    to_entity=end,
                    evidence_id="" if provenance is None else provenance.evidence_id,
                    observed_at="" if provenance is None else provenance.observed_at,
                )
            )
        return EntityPath(
            case_id=case.id,
            source=source,
            target=target,
            steps=tuple(steps),
            length=len(steps),
            found=True,
            max_length_searched=max_length,
            reason=SignalReason.PATH_FOUND,
            analytics_version=self._policy.analytics_version,
        )

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
