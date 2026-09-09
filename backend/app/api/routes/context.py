"""Agency context selection.

The requested context is a *claim*: it is built from the caller's live role and
clearance, handed to SecurityService for a decision, and only written to the
session if the decision allows it. An unknown agency travels the same path and
is denied by the grants check, so the response never discloses which agencies
exist and the denial is still audited.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import (
    get_agency_directory,
    get_current_session,
    get_current_user,
    get_security_service,
    get_session_store,
)
from app.api.errors import AUTHENTICATED_ERRORS, ApiError, forbidden
from app.api.schemas import ContextResponse, ContextSwitchRequest
from app.core.domain.agency import Agency, AgencyContext
from app.core.domain.identity import User
from app.security.agencies import InMemoryAgencyDirectory
from app.security.service import SecurityService
from app.security.session.models import Session
from app.security.session.store import SQLiteSessionStore

router = APIRouter(tags=["context"])


@router.post(
    "/context/switch",
    response_model=ContextResponse,
    responses=AUTHENTICATED_ERRORS,
)
def switch_context(
    payload: ContextSwitchRequest,
    session: Session = Depends(get_current_session),
    user: User = Depends(get_current_user),
    directory: InMemoryAgencyDirectory = Depends(get_agency_directory),
    security: SecurityService = Depends(get_security_service),
    sessions: SQLiteSessionStore = Depends(get_session_store),
) -> ContextResponse:
    if user.clearance is None:
        raise forbidden(ApiError.CLEARANCE_INVALID)
    if not user.roles:
        raise forbidden(ApiError.AGENCY_ACCESS_DENIED)

    agency = directory.get(payload.agency_id) or Agency(
        id=payload.agency_id, name=payload.agency_id, plugin_id=""
    )
    role = user.roles[0]
    claimed = AgencyContext(
        agency=agency,
        user_id=user.id,
        role=role,
        clearance=user.clearance,
        department=payload.department,
        unit=payload.unit,
    )

    decision = security.authorize_agency_context(
        user, claimed, correlation_id=session.correlation_id
    )
    if not decision.grants_access:
        raise forbidden(ApiError.AGENCY_ACCESS_DENIED)

    sessions.set_active_context(
        session_id=session.session_id,
        agency_id=agency.id,
        role_id=role.id,
        department=payload.department,
        unit=payload.unit,
    )
    return ContextResponse(
        agency_id=agency.id,
        agency_name=agency.name,
        role=role.name,
        clearance_level=user.clearance.level_code,
        department=payload.department,
        unit=payload.unit,
    )
