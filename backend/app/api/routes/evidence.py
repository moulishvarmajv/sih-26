"""Protected evidence endpoints.

Thin by design: resolve the authenticated context, hand off to EvidenceService,
map service errors onto deterministic codes. No authorization logic, no masking
and no persistence decisions live here.

GET routes never process anything — reading an analysis that does not exist
returns ANALYSIS_NOT_AVAILABLE rather than quietly starting a run.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import (
    get_case_repository,
    get_current_agency_context,
    get_current_user,
    get_evidence_service,
)
from app.api.errors import ApiError, forbidden, http_error
from app.api.schemas import (
    AnalysisResultResponse,
    EvidenceListResponse,
    EvidenceSummary,
    EvidenceViewResponse,
    EvidenceVersionResponse,
    EvidenceVersionsResponse,
)
from app.core.domain.agency import AgencyContext
from app.core.domain.case import Case
from app.core.domain.identity import User
from app.core.evidence.analysis import CDR_SUMMARY
from app.core.evidence.service import (
    AnalysisView,
    EvidenceAccessDenied,
    EvidenceNotFound,
    EvidenceService,
    EvidenceView,
)
from app.infrastructure.sqlite_case_repository import SQLiteCaseRepository

router = APIRouter(tags=["evidence"])


def _require_context(context: AgencyContext | None) -> AgencyContext:
    if context is None:
        raise forbidden(ApiError.NO_ACTIVE_CONTEXT)
    return context


def _require_case(cases: SQLiteCaseRepository, case_id: str) -> Case:
    case = cases.get(case_id)
    if case is None:
        raise forbidden(ApiError.CASE_ACCESS_DENIED)
    return case


@router.get("/cases/{case_id}/evidence", response_model=EvidenceListResponse)
def list_case_evidence(
    case_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceListResponse:
    case = _require_case(cases, case_id)
    try:
        records = service.list_case_evidence(user, _require_context(context), case)
    except EvidenceAccessDenied:
        raise forbidden(ApiError.CASE_ACCESS_DENIED) from None
    return EvidenceListResponse(
        case_id=case_id, evidence=[_summary(record) for record in records]
    )


@router.get("/evidence/{evidence_id}", response_model=EvidenceViewResponse)
def view_evidence(
    evidence_id: str,
    case_id: str,
    version_id: str | None = None,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceViewResponse:
    case = _require_case(cases, case_id)
    try:
        view = service.view_evidence(
            user, _require_context(context), case, evidence_id, version_id
        )
    except EvidenceAccessDenied:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    except EvidenceNotFound:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    return _view_response(view)


@router.get("/evidence/{evidence_id}/versions", response_model=EvidenceVersionsResponse)
def list_versions(
    evidence_id: str,
    case_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceService = Depends(get_evidence_service),
) -> EvidenceVersionsResponse:
    case = _require_case(cases, case_id)
    try:
        versions = service.get_evidence_versions(
            user, _require_context(context), case, evidence_id
        )
    except EvidenceAccessDenied:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    except EvidenceNotFound:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    return EvidenceVersionsResponse(
        evidence_id=evidence_id,
        versions=[
            EvidenceVersionResponse(
                version_id=version.version_id,
                version_number=version.version_number,
                content_hash=version.content_hash,
                source_reference=version.source_reference,
                ingested_at=version.ingested_at,
                state=version.state.value,
            )
            for version in versions
        ],
    )


@router.get("/evidence/{evidence_id}/analysis", response_model=AnalysisResultResponse)
def get_analysis(
    evidence_id: str,
    case_id: str,
    task_type: str = CDR_SUMMARY,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceService = Depends(get_evidence_service),
) -> AnalysisResultResponse:
    """Read an existing result. Does not process anything."""
    case = _require_case(cases, case_id)
    try:
        view = service.get_analysis_result(
            user, _require_context(context), case, evidence_id, task_type
        )
    except EvidenceAccessDenied:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    except EvidenceNotFound:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    if view is None:
        raise http_error(ApiError.ANALYSIS_NOT_AVAILABLE, 404)
    return _analysis_response(view)


@router.post("/evidence/{evidence_id}/analyze", response_model=AnalysisResultResponse)
def analyze(
    evidence_id: str,
    case_id: str,
    task_type: str = CDR_SUMMARY,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceService = Depends(get_evidence_service),
) -> AnalysisResultResponse:
    """Return the current result if there is one, otherwise compute it."""
    case = _require_case(cases, case_id)
    try:
        view = service.analyze_evidence(
            user, _require_context(context), case, evidence_id, task_type
        )
    except EvidenceAccessDenied:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    except EvidenceNotFound:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    return _analysis_response(view)


@router.post("/evidence/{evidence_id}/reanalyze", response_model=AnalysisResultResponse)
def reanalyze(
    evidence_id: str,
    case_id: str,
    task_type: str = CDR_SUMMARY,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: EvidenceService = Depends(get_evidence_service),
) -> AnalysisResultResponse:
    """Deliberately create a new processing run, keeping the previous result."""
    case = _require_case(cases, case_id)
    try:
        view = service.reanalyze_evidence(
            user, _require_context(context), case, evidence_id, task_type
        )
    except EvidenceAccessDenied:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    except EvidenceNotFound:
        raise forbidden(ApiError.EVIDENCE_ACCESS_DENIED) from None
    return _analysis_response(view)


def _summary(record) -> EvidenceSummary:
    return EvidenceSummary(
        evidence_id=record.id,
        case_id=record.case_id,
        source_id=record.source_id,
        source_record_id=record.source_record_id,
        classification=record.classification.value,
        state=record.state.value,
        security_level=record.security_level,
        created_at=record.created_at,
    )


def _view_response(view: EvidenceView) -> EvidenceViewResponse:
    return EvidenceViewResponse(
        evidence=_summary(view.evidence),
        version=EvidenceVersionResponse(
            version_id=view.version.version_id,
            version_number=view.version.version_number,
            content_hash=view.version.content_hash,
            source_reference=view.version.source_reference,
            ingested_at=view.version.ingested_at,
            state=view.version.state.value,
        ),
        payload=view.payload,
        decision=view.decision.effect.value,
        masked_fields=list(view.masked_fields),
    )


def _analysis_response(view: AnalysisView) -> AnalysisResultResponse:
    return AnalysisResultResponse(
        result_id=view.result.result_id,
        run_id=view.result.run_id,
        evidence_id=view.result.evidence_id,
        evidence_version_id=view.result.evidence_version_id,
        task_type=view.result.task_type,
        classification=view.result.classification.value,
        state=view.result.state.value,
        output_hash=view.result.output_hash,
        created_at=view.result.created_at,
        reused=view.reused,
        payload=view.payload,
    )
