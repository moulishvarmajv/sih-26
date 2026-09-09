"""Protected entity-resolution endpoints.

Thin by design: resolve the authenticated context, hand off to
EntityResolutionService, map service errors onto deterministic codes. No
authorization logic, no scoring and no masking decisions live here.

GET routes never resolve anything. Running resolution is an explicit POST,
because it is a processing step that creates decisions and can write inferred
links — reading a case's resolutions must never do that as a side effect.

Approve and reject go through the service so that a human outcome is recorded as
a human outcome, distinct from anything the scorer decided on its own.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.dependencies import (
    get_case_repository,
    get_current_agency_context,
    get_current_user,
    get_resolution_service,
)
from app.api.errors import (
    AUTHENTICATED_ERRORS,
    GRAPH_ERRORS,
    RESOLUTION_REVIEW_ERRORS,
    ApiError,
    forbidden,
    http_error,
)
from app.api.schemas import (
    CandidateOriginDTO,
    EntityResolutionListResponse,
    EntityResolutionResponse,
    MatchEvidenceDTO,
    MatchExplanationDTO,
    ResolutionConflictDTO,
    ResolutionReviewDTO,
    ResolutionReviewRequest,
    ResolutionRunResponse,
    ResolvedEntityDTO,
)
from app.core.domain.agency import AgencyContext
from app.core.domain.case import Case
from app.core.domain.identity import User
from app.core.evidence.models import TrustClassification
from app.core.graph.repository import GraphUnavailable
from app.core.resolution.models import (
    BlockingStrategy,
    EntityObservationRef,
    ResolutionStatus,
    ReviewAction,
)
from app.core.resolution.service import (
    EntityResolutionService,
    ResolutionAccessDenied,
    ResolutionNotFound,
    ResolutionNotOpen,
    ResolutionRunSummary,
    ResolutionView,
)
from app.infrastructure.sqlite_case_repository import SQLiteCaseRepository

router = APIRouter(tags=["entity-resolution"])

#: A candidate's blocking key is a raw identifier — a phone number or an IMEI —
#: so responses name the attribute it blocked on and never the value.
_BLOCKING_ATTRIBUTES = {
    BlockingStrategy.EXACT_PHONE: "phone",
    BlockingStrategy.EXACT_IMEI: "imei",
    BlockingStrategy.EXACT_ACCOUNT: "account_number",
    BlockingStrategy.SOURCE_IDENTIFIER: "source_entity_ref",
    BlockingStrategy.NAME_LOCALITY: "name+locality",
}


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


@router.post(
    "/cases/{case_id}/entity-resolution/run",
    response_model=ResolutionRunResponse,
    responses={**AUTHENTICATED_ERRORS, **GRAPH_ERRORS},
)
def run_resolution(
    case_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EntityResolutionService = Depends(get_resolution_service),
) -> ResolutionRunResponse:
    """Resolve entities over the evidence this reader is authorized for."""
    case = _require_case(cases, case_id)
    try:
        summary = service.run(user, _require_context(context), case)
    except ResolutionAccessDenied:
        raise forbidden(ApiError.RESOLUTION_ACCESS_DENIED) from None
    except GraphUnavailable:
        raise http_error(
            ApiError.GRAPH_UNAVAILABLE, status.HTTP_503_SERVICE_UNAVAILABLE
        ) from None
    return _run_response(summary)


@router.get(
    "/cases/{case_id}/entity-resolution",
    response_model=EntityResolutionListResponse,
    responses=AUTHENTICATED_ERRORS,
)
def list_resolutions(
    case_id: str,
    # Typed as the enum so FastAPI validates it and documents the allowed
    # values. An unknown value is a 422 about the request, not a denial —
    # reporting it as RESOLUTION_ACCESS_DENIED conflated a typo with a
    # security outcome and made both harder to read.
    status_filter: ResolutionStatus | None = None,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EntityResolutionService = Depends(get_resolution_service),
) -> EntityResolutionListResponse:
    """Read existing resolutions. Never resolves anything."""
    case = _require_case(cases, case_id)
    statuses = [status_filter] if status_filter is not None else None
    try:
        views = service.list_resolutions(user, _require_context(context), case, statuses)
    except ResolutionAccessDenied:
        raise forbidden(ApiError.RESOLUTION_ACCESS_DENIED) from None
    return EntityResolutionListResponse(
        case_id=case_id, resolutions=[_resolution_response(view) for view in views]
    )


@router.get(
    "/cases/{case_id}/entity-resolution/{resolution_id}",
    response_model=EntityResolutionResponse,
    responses=AUTHENTICATED_ERRORS,
)
def get_resolution(
    case_id: str,
    resolution_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EntityResolutionService = Depends(get_resolution_service),
) -> EntityResolutionResponse:
    case = _require_case(cases, case_id)
    try:
        view = service.get_resolution(user, _require_context(context), case, resolution_id)
    except (ResolutionAccessDenied, ResolutionNotFound):
        # Unknown and unauthorized return the same code, so neither can be
        # enumerated by probing resolution ids.
        raise forbidden(ApiError.RESOLUTION_ACCESS_DENIED) from None
    return _resolution_response(view)


@router.post(
    "/cases/{case_id}/entity-resolution/{resolution_id}/approve",
    response_model=EntityResolutionResponse,
    responses={**AUTHENTICATED_ERRORS, **RESOLUTION_REVIEW_ERRORS},
)
def approve_resolution(
    case_id: str,
    resolution_id: str,
    body: ResolutionReviewRequest | None = None,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EntityResolutionService = Depends(get_resolution_service),
) -> EntityResolutionResponse:
    return _review(
        ReviewAction.APPROVE, case_id, resolution_id, body, user, context, cases, service
    )


@router.post(
    "/cases/{case_id}/entity-resolution/{resolution_id}/reject",
    response_model=EntityResolutionResponse,
    responses={**AUTHENTICATED_ERRORS, **RESOLUTION_REVIEW_ERRORS},
)
def reject_resolution(
    case_id: str,
    resolution_id: str,
    body: ResolutionReviewRequest | None = None,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EntityResolutionService = Depends(get_resolution_service),
) -> EntityResolutionResponse:
    return _review(
        ReviewAction.REJECT, case_id, resolution_id, body, user, context, cases, service
    )


@router.post(
    "/cases/{case_id}/entity-resolution/{resolution_id}/defer",
    response_model=EntityResolutionResponse,
    responses={**AUTHENTICATED_ERRORS, **RESOLUTION_REVIEW_ERRORS},
)
def defer_resolution(
    case_id: str,
    resolution_id: str,
    body: ResolutionReviewRequest | None = None,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EntityResolutionService = Depends(get_resolution_service),
) -> EntityResolutionResponse:
    """Record that a reviewer looked and left it open; the status does not change."""
    return _review(
        ReviewAction.DEFER, case_id, resolution_id, body, user, context, cases, service
    )


def _review(
    action: ReviewAction,
    case_id: str,
    resolution_id: str,
    body: ResolutionReviewRequest | None,
    user: User,
    context: AgencyContext | None,
    cases: SQLiteCaseRepository,
    service: EntityResolutionService,
) -> EntityResolutionResponse:
    case = _require_case(cases, case_id)
    try:
        view = service.review(
            user,
            _require_context(context),
            case,
            resolution_id,
            action,
            reason=body.reason if body else None,
        )
    except (ResolutionAccessDenied, ResolutionNotFound):
        raise forbidden(ApiError.RESOLUTION_ACCESS_DENIED) from None
    except ResolutionNotOpen:
        raise http_error(ApiError.RESOLUTION_NOT_OPEN, status.HTTP_409_CONFLICT) from None
    return _resolution_response(view)


def _run_response(summary: ResolutionRunSummary) -> ResolutionRunResponse:
    return ResolutionRunResponse(
        case_id=summary.case_id,
        policy_version=summary.policy_version,
        evidence_considered=summary.evidence_considered,
        evidence_excluded=summary.evidence_excluded,
        observations=summary.observations,
        candidates=summary.candidates,
        auto_accepted=summary.auto_accepted,
        review_required=summary.review_required,
        unresolved=summary.unresolved,
        superseded=summary.superseded,
        unchanged=summary.unchanged,
        links_projected=summary.links_projected,
        graph_available=summary.graph_available,
    )


def _resolution_response(view: ResolutionView) -> EntityResolutionResponse:
    decision = view.decision
    candidate = view.candidate
    return EntityResolutionResponse(
        resolution_id=decision.resolution_id,
        lineage_id=decision.lineage_id,
        resolution_version=decision.resolution_version,
        case_id=decision.case_id,
        entity_type=decision.entity_type.value,
        status=decision.status.value,
        left=_entity_dto(decision.left, view.left_label),
        right=_entity_dto(decision.right, view.right_label),
        explanation=_explanation_dto(view),
        policy_version=decision.policy_version,
        created_at=decision.created_at,
        decided_at=decision.decided_at,
        decided_by=decision.decided_by,
        decision_actor=None
        if decision.decision_actor is None
        else decision.decision_actor.value,
        decision_reason=decision.decision_reason,
        superseded_by=decision.superseded_by,
        trust_class=TrustClassification.INFERRED.value,
        candidate=None
        if candidate is None
        else CandidateOriginDTO(
            candidate_id=candidate.candidate_id,
            blocking_strategy=candidate.blocking_strategy.value,
            blocking_key_attribute=_BLOCKING_ATTRIBUTES.get(
                candidate.blocking_strategy, candidate.blocking_strategy.value.lower()
            ),
            created_at=candidate.created_at,
        ),
        reviews=[
            ResolutionReviewDTO(
                reviewer_id=review.reviewer_id,
                action=review.action.value,
                reviewed_at=review.reviewed_at,
                reason=review.reason,
            )
            for review in view.reviews
        ],
        masked_fields=list(view.masked_fields),
    )


def _entity_dto(ref: EntityObservationRef, label: str) -> ResolvedEntityDTO:
    return ResolvedEntityDTO(
        entity_ref=ref.entity_ref,
        entity_type=ref.entity_type.value,
        label=label,
        source_id=ref.source_id,
        evidence_id=ref.evidence_id,
        evidence_version_id=ref.evidence_version_id,
        observed_at=ref.observed_at,
    )


def _explanation_dto(view: ResolutionView) -> MatchExplanationDTO:
    score = view.decision.score
    return MatchExplanationDTO(
        recommendation=score.recommendation.value,
        score=round(score.score, 4),
        evidence_weight=round(score.evidence_weight, 4),
        confidence=score.confidence.value,
        confidence_floor=score.confidence_floor,
        policy_version=score.policy_version,
        reasons=[reason.value for reason in score.reasons],
        evidence=[
            MatchEvidenceDTO(
                signal=item.signal.value,
                attribute=item.attribute,
                outcome=item.outcome.value,
                weight=round(item.weight, 4),
                contribution=round(item.contribution, 4),
                similarity=None if item.similarity is None else round(item.similarity, 4),
            )
            for item in score.evidence
        ],
        conflicts=[
            ResolutionConflictDTO(
                attribute=conflict.attribute,
                rule=conflict.rule,
                penalty=round(conflict.penalty, 4),
                blocks_auto_accept=conflict.blocks_auto_accept,
                similarity=None
                if conflict.similarity is None
                else round(conflict.similarity, 4),
            )
            for conflict in score.conflicts
        ],
    )
