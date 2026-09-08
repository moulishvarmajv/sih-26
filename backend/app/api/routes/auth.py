"""Login and authenticated-identity endpoints.

Every non-success login collapses into one AUTHENTICATION_FAILED response, so
the API never reveals whether a username exists or an account is disabled. The
server-side audit log keeps the real reason.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import (
    get_agency_directory,
    get_authentication_service,
    get_current_session,
    get_current_user,
    get_grant_repository,
    get_security_policy,
)
from app.api.errors import ApiError, unauthorized
from app.api.schemas import (
    AgencyResponse,
    ClearanceResponse,
    LoginRequest,
    LoginResponse,
    MeResponse,
    SessionResponse,
)
from app.core.domain.identity import User
from app.infrastructure.clock import utc_now_iso
from app.security.agencies import InMemoryAgencyDirectory
from app.security.authentication import AuthenticationError, AuthenticationService
from app.security.clearance.verification import ClearanceState, verify_clearance
from app.security.grants import InMemoryAccessGrantRepository
from app.security.identity.models import Credentials
from app.security.policy.loader import SecurityPolicy
from app.security.session.models import Session

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    auth: AuthenticationService = Depends(get_authentication_service),
) -> LoginResponse:
    try:
        result = auth.login(Credentials(username=payload.username, password=payload.password))
    except AuthenticationError:
        raise unauthorized(ApiError.AUTHENTICATION_FAILED) from None

    return LoginResponse(
        token=result.token,
        session=SessionResponse(
            session_id=result.session.session_id, expires_at=result.session.expires_at
        ),
        user_id=result.user.id,
        display_name=result.user.display_name,
        clearance=_clearance_response(result.user, result.clearance_verified),
    )


@router.get("/me", response_model=MeResponse)
def me(
    session: Session = Depends(get_current_session),
    user: User = Depends(get_current_user),
    grants: InMemoryAccessGrantRepository = Depends(get_grant_repository),
    directory: InMemoryAgencyDirectory = Depends(get_agency_directory),
    policy: SecurityPolicy = Depends(get_security_policy),
) -> MeResponse:
    authorized = sorted(grants.agencies_for_user(user.id))
    agencies = [
        AgencyResponse(agency_id=agency.id, name=agency.name)
        for agency in (directory.get(agency_id) for agency_id in authorized)
        if agency is not None
    ]
    return MeResponse(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        roles=[role.name for role in user.roles],
        clearance=_clearance_response(
            user,
            verify_clearance(user.clearance, policy.clearance, utc_now_iso())
            is ClearanceState.VALID,
        ),
        authorized_agencies=agencies,
        active_agency_id=session.active_agency_id,
        session=SessionResponse(session_id=session.session_id, expires_at=session.expires_at),
    )


def _clearance_response(user: User, verified: bool) -> ClearanceResponse:
    if user.clearance is None:
        return ClearanceResponse(level=None, verified=False)
    return ClearanceResponse(
        level=user.clearance.level_code,
        verified=verified,
        expires_at=user.clearance.expires_at,
    )
