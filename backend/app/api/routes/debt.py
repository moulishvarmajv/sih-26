"""Protected evidence-debt endpoints.

Thin by design: resolve the authenticated context, hand off to
EvidenceDebtService, map service errors onto deterministic codes. No detector,
no weight and no scope decision lives here.

The GET routes recalculate over the reader's authorized view and persist
nothing — no snapshot, no item. Recording a calculation is an explicit POST, for
the same reason that viewing evidence never starts a processing run.

Every response identifies an entity by the hashed `entity_ref` resolution and
the graph already publish, and names attributes and rules rather than quoting
them. The natural key never reaches this module, so no route here can disclose
one.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from app.api.dependencies import (
    get_case_repository,
    get_current_agency_context,
    get_current_user,
    get_debt_service,
)
from app.api.errors import (
    AUTHENTICATED_ERRORS,
    DEBT_ERRORS,
    ApiError,
    forbidden,
    http_error,
)
from app.api.schemas import (
    DebtAcknowledgeRequest,
    DebtBreakdownDTO,
    DebtChangeDTO,
    DebtSubjectDTO,
    DebtWeightingDTO,
    EvidenceDebtBreakdownResponse,
    EvidenceDebtItemDTO,
    EvidenceDebtItemDetailResponse,
    EvidenceDebtItemListResponse,
    EvidenceDebtResponse,
)
from app.core.debt.models import (
    DebtCategory,
    DebtChange,
    DebtStatus,
    EvidenceDebtBreakdown,
    EvidenceDebtItem,
)
from app.core.debt.service import (
    DebtAccessDenied,
    DebtItemNotFound,
    EvidenceDebtReport,
    EvidenceDebtService,
)
from app.core.domain.agency import AgencyContext
from app.core.domain.case import Case
from app.core.domain.identity import User
from app.infrastructure.sqlite_case_repository import SQLiteCaseRepository

router = APIRouter(tags=["evidence-debt"])


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
    "/cases/{case_id}/evidence-debt",
    response_model=EvidenceDebtResponse,
    responses=AUTHENTICATED_ERRORS,
)
def evidence_debt(
    case_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceDebtService = Depends(get_debt_service),
) -> EvidenceDebtResponse:
    """The case's current evidence debt, and what changed since the last record.

    A quality metric over the reader's authorized evidence. Not guilt, not case
    strength, not completion: a HIGH band means this investigation has support
    gaps, and says nothing about anyone in it.
    """
    case = _require_case(cases, case_id)
    try:
        report = service.report(user, _require_context(context), case)
    except DebtAccessDenied:
        raise forbidden(ApiError.DEBT_ACCESS_DENIED) from None
    return _report_response(report)


@router.get(
    "/cases/{case_id}/evidence-debt/breakdown",
    response_model=EvidenceDebtBreakdownResponse,
    responses=AUTHENTICATED_ERRORS,
)
def evidence_debt_breakdown(
    case_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceDebtService = Depends(get_debt_service),
) -> EvidenceDebtBreakdownResponse:
    """Per-category contributions. Every category is reported, including empty ones."""
    case = _require_case(cases, case_id)
    try:
        snapshot = service.calculate(user, _require_context(context), case)
    except DebtAccessDenied:
        raise forbidden(ApiError.DEBT_ACCESS_DENIED) from None
    return EvidenceDebtBreakdownResponse(
        case_id=snapshot.case_id,
        total_debt=round(snapshot.total_debt, 4),
        normalized_debt=snapshot.normalized_debt,
        band=snapshot.band.value,
        item_count=snapshot.item_count,
        breakdown=[_breakdown_dto(entry) for entry in snapshot.breakdown],
        policy_version=snapshot.policy_version,
        debt_engine_version=snapshot.debt_engine_version,
    )


@router.get(
    "/cases/{case_id}/evidence-debt/items",
    response_model=EvidenceDebtItemListResponse,
    responses=AUTHENTICATED_ERRORS,
)
def evidence_debt_items(
    case_id: str,
    category: DebtCategory | None = Query(default=None),
    item_status: DebtStatus | None = Query(default=None, alias="status"),
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceDebtService = Depends(get_debt_service),
) -> EvidenceDebtItemListResponse:
    """Open gaps as currently detected, plus what has been recorded as resolved."""
    case = _require_case(cases, case_id)
    try:
        items = service.list_items(
            user,
            _require_context(context),
            case,
            categories=[category] if category is not None else None,
            statuses=[item_status] if item_status is not None else None,
        )
    except DebtAccessDenied:
        raise forbidden(ApiError.DEBT_ACCESS_DENIED) from None
    return EvidenceDebtItemListResponse(
        case_id=case_id,
        item_count=len(items),
        items=[_item_dto(item) for item in items],
    )


@router.get(
    "/cases/{case_id}/evidence-debt/items/{debt_id}",
    response_model=EvidenceDebtItemDetailResponse,
    responses=AUTHENTICATED_ERRORS,
)
def evidence_debt_item(
    case_id: str,
    debt_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceDebtService = Depends(get_debt_service),
) -> EvidenceDebtItemDetailResponse:
    """One item and every recorded version of it."""
    case = _require_case(cases, case_id)
    try:
        item = service.get_item(user, _require_context(context), case, debt_id)
        history = service.item_history(user, _require_context(context), case, debt_id)
    except (DebtAccessDenied, DebtItemNotFound):
        # Unknown and unauthorized answer alike, so debt ids cannot be probed
        # for the existence of gaps in evidence the reader may not see.
        raise forbidden(ApiError.DEBT_ACCESS_DENIED) from None
    return EvidenceDebtItemDetailResponse(
        item=_item_dto(item), history=[_item_dto(entry) for entry in history]
    )


@router.post(
    "/cases/{case_id}/evidence-debt/recalculate",
    response_model=EvidenceDebtResponse,
    responses=AUTHENTICATED_ERRORS,
)
def recalculate_evidence_debt(
    case_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceDebtService = Depends(get_debt_service),
) -> EvidenceDebtResponse:
    """Compute the case's debt and record the snapshot.

    Idempotent: recalculating over unchanged investigation state records a new
    snapshot with the same totals and does not manufacture new items.
    """
    case = _require_case(cases, case_id)
    try:
        report = service.recalculate(user, _require_context(context), case)
    except DebtAccessDenied:
        raise forbidden(ApiError.DEBT_ACCESS_DENIED) from None
    return _report_response(report)


@router.post(
    "/cases/{case_id}/evidence-debt/items/{debt_id}/acknowledge",
    response_model=EvidenceDebtItemDetailResponse,
    responses={**AUTHENTICATED_ERRORS, **DEBT_ERRORS},
)
def acknowledge_evidence_debt_item(
    case_id: str,
    debt_id: str,
    request: DebtAcknowledgeRequest | None = None,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceDebtService = Depends(get_debt_service),
) -> EvidenceDebtItemDetailResponse:
    """Record that a person has seen this gap and accepts that it stands.

    Beyond the five read/recalculate endpoints because the lifecycle needs it:
    an ACKNOWLEDGED state that no client can reach would be a state that only
    pretends to work, and recalculation is required not to undo it.
    """
    case = _require_case(cases, case_id)
    try:
        item = service.acknowledge_item(
            user,
            _require_context(context),
            case,
            debt_id,
            reason=None if request is None else request.reason,
        )
        history = service.item_history(user, _require_context(context), case, debt_id)
    except DebtItemNotFound:
        raise http_error(ApiError.DEBT_ITEM_NOT_FOUND, status.HTTP_404_NOT_FOUND) from None
    except DebtAccessDenied:
        raise forbidden(ApiError.DEBT_ACCESS_DENIED) from None
    return EvidenceDebtItemDetailResponse(
        item=_item_dto(item), history=[_item_dto(entry) for entry in history]
    )


# -- mapping -----------------------------------------------------------------


def _item_dto(item: EvidenceDebtItem) -> EvidenceDebtItemDTO:
    return EvidenceDebtItemDTO(
        debt_id=item.debt_id,
        case_id=item.case_id,
        category=item.category.value,
        severity=item.severity.value,
        status=item.status.value,
        reason=item.reason.value,
        subject=DebtSubjectDTO(
            subject_type=item.subject.subject_type.value,
            reference=item.subject.reference,
            entity_refs=list(item.subject.entity_refs),
        ),
        weighting=DebtWeightingDTO(
            category_weight=round(item.weighting.category_weight, 4),
            severity_multiplier=round(item.weighting.severity_multiplier, 4),
            scope_factor=round(item.weighting.scope_factor, 4),
            criticality_factor=round(item.weighting.criticality_factor, 4),
            affected_scope=item.weighting.affected_scope,
            weighted_contribution=round(item.weighting.weighted_contribution, 4),
        ),
        explanation=dict(item.explanation),
        supporting_evidence_ids=list(item.supporting_evidence_ids),
        related_resolution_ids=list(item.related_resolution_ids),
        related_finding_ids=list(item.related_finding_ids),
        actionable=item.actionable,
        priority=item.priority,
        blocking_reason=item.blocking_reason.value,
        required_capability=item.required_capability,
        created_at=item.created_at,
        calculated_at=item.calculated_at,
        version=item.version,
        status_changed_at=item.status_changed_at,
        status_changed_by=item.status_changed_by,
        status_reason=item.status_reason,
        policy_version=item.policy_version,
        debt_engine_version=item.debt_engine_version,
    )


def _breakdown_dto(entry: EvidenceDebtBreakdown) -> DebtBreakdownDTO:
    return DebtBreakdownDTO(
        category=entry.category.value,
        item_count=entry.item_count,
        weighted_contribution=round(entry.weighted_contribution, 4),
        share=round(entry.share, 4),
        severity_counts=dict(entry.severity_counts),
    )


def _change_dto(change: DebtChange) -> DebtChangeDTO:
    return DebtChangeDTO(
        previous_snapshot_id=change.previous_snapshot_id,
        previous_total=round(change.previous_total, 4),
        delta=round(change.delta, 4),
        resolved_debt_ids=list(change.resolved_debt_ids),
        introduced_debt_ids=list(change.introduced_debt_ids),
        unchanged_count=change.unchanged_count,
    )


def _report_response(report: EvidenceDebtReport) -> EvidenceDebtResponse:
    snapshot = report.snapshot
    return EvidenceDebtResponse(
        snapshot_id=snapshot.snapshot_id,
        case_id=snapshot.case_id,
        calculated_at=snapshot.calculated_at,
        total_debt=round(snapshot.total_debt, 4),
        normalized_debt=snapshot.normalized_debt,
        band=snapshot.band.value,
        item_count=snapshot.item_count,
        evidence_in_scope=snapshot.evidence_in_scope,
        excluded_evidence_count=snapshot.excluded_evidence_count,
        persisted=snapshot.persisted,
        breakdown=[_breakdown_dto(entry) for entry in snapshot.breakdown],
        top_items=[_item_dto(item) for item in snapshot.top_items],
        change=_change_dto(report.change),
        policy_version=snapshot.policy_version,
        debt_engine_version=snapshot.debt_engine_version,
    )
