"""Protected graph-analytics endpoints.

Thin by design: resolve the authenticated context, hand off to
GraphAnalyticsService, map service errors onto deterministic codes. No metric,
no threshold and no masking decision lives here.

The GET routes compute a read-model over the reader's authorized graph and
persist nothing — no run, no signal. Recording signals is an explicit POST, for
the same reason that viewing evidence never starts a processing run: a read
should not leave state behind, and a stored finding should be something someone
chose to create.

Every response identifies an entity by its hashed id and its masked label. The
natural key never reaches this module, so no route here can disclose one.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.dependencies import (
    get_analytics_service,
    get_case_repository,
    get_current_agency_context,
    get_current_user,
)
from app.api.errors import (
    AUTHENTICATED_ERRORS,
    GRAPH_ERRORS,
    ANALYTICS_ERRORS,
    ApiError,
    forbidden,
    http_error,
)
from app.api.schemas import (
    AnalyticsEntityDTO,
    AnalyticsOverviewResponse,
    AnalyticsRunResponse,
    BridgeDTO,
    ComponentDTO,
    ConnectivityDTO,
    EntityAnalyticsResponse,
    PathResponse,
    PathStepDTO,
    SignalListResponse,
    SignalMetricDTO,
    SignalResponse,
    TemporalWindowDTO,
)
from app.core.analytics.models import (
    AnalyticsEntity,
    AnalyticsRun,
    BridgeMetric,
    ConnectivityMetric,
    EntityPath,
    GraphComponent,
    InvestigationSignal,
    SignalType,
    TemporalWindow,
)
from app.core.analytics.service import (
    AnalyticsAccessDenied,
    AnalyticsEntityNotFound,
    AnalyticsOverview,
    EntityAnalytics,
    GraphAnalyticsService,
    SignalNotFound,
)
from app.core.domain.agency import AgencyContext
from app.core.domain.case import Case
from app.core.domain.identity import User
from app.core.graph.repository import GraphUnavailable
from app.infrastructure.sqlite_case_repository import SQLiteCaseRepository

router = APIRouter(tags=["analytics"])


def _require_context(context: AgencyContext | None) -> AgencyContext:
    if context is None:
        raise forbidden(ApiError.NO_ACTIVE_CONTEXT)
    return context


def _require_case(cases: SQLiteCaseRepository, case_id: str) -> Case:
    case = cases.get(case_id)
    if case is None:
        # Same code as an unauthorized case, so neither can be enumerated.
        raise forbidden(ApiError.CASE_ACCESS_DENIED)
    return case


@router.get(
    "/cases/{case_id}/analytics/overview",
    response_model=AnalyticsOverviewResponse,
    responses={**AUTHENTICATED_ERRORS, **GRAPH_ERRORS},
)
def analytics_overview(
    case_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: GraphAnalyticsService = Depends(get_analytics_service),
) -> AnalyticsOverviewResponse:
    """The shape of the case graph this reader is authorized to see."""
    case = _require_case(cases, case_id)
    try:
        overview = service.overview(user, _require_context(context), case)
    except AnalyticsAccessDenied:
        raise forbidden(ApiError.ANALYTICS_ACCESS_DENIED) from None
    except GraphUnavailable:
        raise http_error(
            ApiError.GRAPH_UNAVAILABLE, status.HTTP_503_SERVICE_UNAVAILABLE
        ) from None
    return _overview_response(overview)


@router.get(
    "/cases/{case_id}/analytics/entity/{entity_id}",
    response_model=EntityAnalyticsResponse,
    responses={**AUTHENTICATED_ERRORS, **ANALYTICS_ERRORS, **GRAPH_ERRORS},
)
def entity_analytics(
    case_id: str,
    entity_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: GraphAnalyticsService = Depends(get_analytics_service),
) -> EntityAnalyticsResponse:
    case = _require_case(cases, case_id)
    try:
        analytics = service.entity_analytics(
            user, _require_context(context), case, entity_id
        )
    except AnalyticsAccessDenied:
        raise forbidden(ApiError.ANALYTICS_ACCESS_DENIED) from None
    except AnalyticsEntityNotFound:
        raise http_error(
            ApiError.ANALYTICS_ENTITY_NOT_FOUND, status.HTTP_404_NOT_FOUND
        ) from None
    except GraphUnavailable:
        raise http_error(
            ApiError.GRAPH_UNAVAILABLE, status.HTTP_503_SERVICE_UNAVAILABLE
        ) from None
    return _entity_response(analytics)


@router.get(
    "/cases/{case_id}/analytics/path/{source_id}/{target_id}",
    response_model=PathResponse,
    responses={**AUTHENTICATED_ERRORS, **ANALYTICS_ERRORS, **GRAPH_ERRORS},
)
def analytics_path(
    case_id: str,
    source_id: str,
    target_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: GraphAnalyticsService = Depends(get_analytics_service),
) -> PathResponse:
    """Shortest observed walk between two entities this reader can already see.

    A path that would have to leave the reader's scope is reported as no path
    rather than as a walk with a gap in it.
    """
    case = _require_case(cases, case_id)
    try:
        path = service.shortest_path(
            user, _require_context(context), case, source_id, target_id
        )
    except AnalyticsAccessDenied:
        raise forbidden(ApiError.ANALYTICS_ACCESS_DENIED) from None
    except AnalyticsEntityNotFound:
        raise http_error(
            ApiError.ANALYTICS_ENTITY_NOT_FOUND, status.HTTP_404_NOT_FOUND
        ) from None
    except GraphUnavailable:
        raise http_error(
            ApiError.GRAPH_UNAVAILABLE, status.HTTP_503_SERVICE_UNAVAILABLE
        ) from None
    return _path_response(path)


@router.post(
    "/cases/{case_id}/analytics/run",
    response_model=AnalyticsRunResponse,
    responses={**AUTHENTICATED_ERRORS, **GRAPH_ERRORS},
)
def run_analytics(
    case_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: GraphAnalyticsService = Depends(get_analytics_service),
) -> AnalyticsRunResponse:
    """Compute signals over the authorized graph and record them."""
    case = _require_case(cases, case_id)
    try:
        run = service.run(user, _require_context(context), case)
    except AnalyticsAccessDenied:
        raise forbidden(ApiError.ANALYTICS_ACCESS_DENIED) from None
    except GraphUnavailable:
        raise http_error(
            ApiError.GRAPH_UNAVAILABLE, status.HTTP_503_SERVICE_UNAVAILABLE
        ) from None
    return _run_response(run)


@router.get(
    "/cases/{case_id}/signals",
    response_model=SignalListResponse,
    responses=AUTHENTICATED_ERRORS,
)
def list_signals(
    case_id: str,
    signal_type: SignalType | None = None,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: GraphAnalyticsService = Depends(get_analytics_service),
) -> SignalListResponse:
    """Read recorded signals. Computes nothing."""
    case = _require_case(cases, case_id)
    try:
        signals = service.list_signals(
            user,
            _require_context(context),
            case,
            [signal_type] if signal_type is not None else None,
        )
    except AnalyticsAccessDenied:
        raise forbidden(ApiError.ANALYTICS_ACCESS_DENIED) from None
    return SignalListResponse(
        case_id=case_id, signals=[_signal_response(signal) for signal in signals]
    )


@router.get(
    "/cases/{case_id}/signals/{signal_id}",
    response_model=SignalResponse,
    responses=AUTHENTICATED_ERRORS,
)
def get_signal(
    case_id: str,
    signal_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: GraphAnalyticsService = Depends(get_analytics_service),
) -> SignalResponse:
    case = _require_case(cases, case_id)
    try:
        signal = service.get_signal(user, _require_context(context), case, signal_id)
    except (AnalyticsAccessDenied, SignalNotFound):
        # Unknown and unauthorized answer alike, so signal ids cannot be probed.
        raise forbidden(ApiError.ANALYTICS_ACCESS_DENIED) from None
    return _signal_response(signal)


# -- mapping -----------------------------------------------------------------


def _entity_dto(entity: AnalyticsEntity) -> AnalyticsEntityDTO:
    return AnalyticsEntityDTO(
        entity_id=entity.entity_id, entity_type=entity.entity_type, label=entity.label
    )


def _connectivity_dto(metric: ConnectivityMetric) -> ConnectivityDTO:
    return ConnectivityDTO(
        entity=_entity_dto(metric.entity),
        degree=metric.degree,
        in_degree=metric.in_degree,
        out_degree=metric.out_degree,
        distinct_neighbours=metric.distinct_neighbours,
        entity_types_touched=list(metric.entity_types_touched),
        rank=metric.rank,
        rank_of=metric.rank_of,
        supporting_relationship_ids=list(metric.supporting_relationship_ids),
        supporting_evidence_ids=list(metric.supporting_evidence_ids),
    )


def _bridge_dto(metric: BridgeMetric) -> BridgeDTO:
    return BridgeDTO(
        entity=_entity_dto(metric.entity),
        groups_separated=metric.groups_separated,
        group_sizes=list(metric.group_sizes),
        separated_side_size=metric.separated_side_size,
        entity_types_spanned=list(metric.entity_types_spanned),
        neighbour_count=metric.neighbour_count,
        rests_on_weak_relationship=metric.rests_on_weak_relationship,
        supporting_relationship_ids=list(metric.supporting_relationship_ids),
        supporting_evidence_ids=list(metric.supporting_evidence_ids),
    )


def _component_dto(component: GraphComponent) -> ComponentDTO:
    return ComponentDTO(
        component_id=component.component_id,
        entity_count=component.entity_count,
        relationship_count=component.relationship_count,
        entity_type_counts=dict(component.entity_type_counts),
        dominant_entity_type=component.dominant_entity_type,
        members=[_entity_dto(member) for member in component.members],
        supporting_evidence_ids=list(component.supporting_evidence_ids),
    )


def _window_dto(window: TemporalWindow) -> TemporalWindowDTO:
    return TemporalWindowDTO(
        window_start=window.window_start,
        window_end=window.window_end,
        event_count=window.event_count,
        mean_event_count=window.mean_event_count,
        concentration_ratio=window.concentration_ratio,
        supporting_relationship_ids=list(window.supporting_relationship_ids),
        supporting_evidence_ids=list(window.supporting_evidence_ids),
    )


def _overview_response(overview: AnalyticsOverview) -> AnalyticsOverviewResponse:
    return AnalyticsOverviewResponse(
        case_id=overview.case_id,
        analytics_version=overview.analytics_version,
        entity_count=overview.entity_count,
        relationship_count=overview.relationship_count,
        evidence_in_scope=overview.evidence_in_scope,
        excluded_evidence_count=overview.excluded_evidence_count,
        truncated=overview.truncated,
        masked_properties=list(overview.masked_properties),
        components=[_component_dto(component) for component in overview.components],
        top_connectivity=[_connectivity_dto(m) for m in overview.top_connectivity],
        bridges=[_bridge_dto(metric) for metric in overview.bridges],
        temporal_concentrations=[_window_dto(w) for w in overview.concentrations],
    )


def _entity_response(analytics: EntityAnalytics) -> EntityAnalyticsResponse:
    return EntityAnalyticsResponse(
        case_id=analytics.case_id,
        analytics_version=analytics.analytics_version,
        entity=_entity_dto(analytics.entity),
        connectivity=_connectivity_dto(analytics.connectivity),
        bridge=None if analytics.bridge is None else _bridge_dto(analytics.bridge),
        component_id=analytics.component_id,
        component_entity_count=analytics.component_entity_count,
        neighbours=[_entity_dto(entity) for entity in analytics.neighbours],
        masked_properties=list(analytics.masked_properties),
    )


def _path_response(path: EntityPath) -> PathResponse:
    return PathResponse(
        case_id=path.case_id,
        analytics_version=path.analytics_version,
        source=_entity_dto(path.source),
        target=_entity_dto(path.target),
        found=path.found,
        length=path.length,
        max_length_searched=path.max_length_searched,
        reason=path.reason.value,
        steps=[
            PathStepDTO(
                relationship_id=step.relationship_id,
                relationship_type=step.relationship_type,
                from_entity=_entity_dto(step.from_entity),
                to_entity=_entity_dto(step.to_entity),
                evidence_id=step.evidence_id,
                observed_at=step.observed_at,
            )
            for step in path.steps
        ],
        entities=[_entity_dto(entity) for entity in path.entities],
        supporting_evidence_ids=list(path.evidence_ids),
    )


def _signal_response(signal: InvestigationSignal) -> SignalResponse:
    return SignalResponse(
        signal_id=signal.signal_id,
        case_id=signal.case_id,
        signal_type=signal.signal_type.value,
        status=signal.status.value,
        version=signal.version,
        score=round(signal.score, 4),
        confidence=signal.confidence,
        reasons=[reason.value for reason in signal.reasons],
        metrics=[
            SignalMetricDTO(
                name=metric.name,
                value=round(metric.value, 4),
                normalized=round(metric.normalized, 4),
                weight=round(metric.weight, 4),
                contribution=round(metric.contribution, 4),
            )
            for metric in signal.metrics
        ],
        entities=[_entity_dto(entity) for entity in signal.entities],
        supporting_relationship_ids=list(signal.supporting_relationship_ids),
        supporting_evidence_ids=list(signal.supporting_evidence_ids),
        detail=dict(signal.detail),
        created_at=signal.created_at,
        analytics_version=signal.analytics_version,
        run_id=signal.run_id,
    )


def _run_response(run: AnalyticsRun) -> AnalyticsRunResponse:
    return AnalyticsRunResponse(
        run_id=run.run_id,
        case_id=run.case_id,
        analytics_version=run.analytics_version,
        executed_at=run.executed_at,
        executed_by=run.executed_by,
        evidence_in_scope=len(run.evidence_ids),
        node_count=run.node_count,
        relationship_count=run.relationship_count,
        signal_count=run.signal_count,
        excluded_evidence_count=run.excluded_evidence_count,
        truncated=run.truncated,
    )
