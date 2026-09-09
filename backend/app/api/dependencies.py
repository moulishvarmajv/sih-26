"""Composition root and the authenticated-session boundary.

Routes obtain identity *only* from these dependencies, which derive everything
from the bearer token. A client-supplied user id is never trusted: there is no
path here that accepts one.

Routes depend on SecurityService, never on the engine, policy document or event
store directly — and never evaluate authorization themselves.

Grants and the agency directory are in-memory for this phase, so they reset on
restart; persisted implementations drop in behind their protocols.
"""
from __future__ import annotations

from functools import lru_cache

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.errors import ApiError, unauthorized
from app.core.config import settings
from app.core.domain.agency import AgencyContext
from app.core.domain.identity import User
from app.core.evidence.analysis import CdrSummaryAnalyzer
from app.core.evidence.service import EvidenceService
from app.core.analytics.policy import AnalyticsPolicy, load_analytics_policy
from app.core.analytics.service import GraphAnalyticsService
from app.core.debt.policy import EvidenceDebtPolicy, load_debt_policy
from app.core.debt.service import EvidenceDebtService
from app.core.graph.service import GraphService
from app.core.resolution.policy import ResolutionPolicy, load_resolution_policy
from app.core.resolution.service import EntityResolutionService
from app.infrastructure.local_object_store import LocalFileEvidenceObjectStore
from app.infrastructure.neo4j_graph_repository import Neo4jGraphRepository
from app.infrastructure.sqlite_case_repository import SQLiteCaseRepository
from app.infrastructure.sqlite_event_store import SQLiteEventStore
from app.infrastructure.sqlite_evidence_repository import SQLiteEvidenceRepository
from app.infrastructure.sqlite_analytics_repository import SQLiteAnalyticsRepository
from app.infrastructure.sqlite_debt_repository import SQLiteEvidenceDebtRepository
from app.infrastructure.sqlite_resolution_repository import SQLiteResolutionRepository
from app.security.agencies import InMemoryAgencyDirectory
from app.security.authentication import (
    AuthenticationService,
    SessionExpired,
    SessionInvalid,
)
from app.security.authorization.policy_engine import ClearanceAuthorizationEngine
from app.security.grants import InMemoryAccessGrantRepository
from app.security.identity.local_provider import LocalIdentityProvider
from app.security.identity.passwords import ScryptPasswordHasher
from app.security.identity.user_store import SQLiteUserStore
from app.security.policy.loader import SecurityPolicy, load_security_policy
from app.security.service import SecurityService
from app.security.session.models import Session
from app.security.session.store import SQLiteSessionStore

bearer_scheme = HTTPBearer(auto_error=False)


@lru_cache(maxsize=1)
def get_security_policy() -> SecurityPolicy:
    return load_security_policy()


@lru_cache(maxsize=1)
def get_event_store() -> SQLiteEventStore:
    return SQLiteEventStore(settings.EVENT_STORE_PATH)


@lru_cache(maxsize=1)
def get_grant_repository() -> InMemoryAccessGrantRepository:
    return InMemoryAccessGrantRepository()


@lru_cache(maxsize=1)
def get_agency_directory() -> InMemoryAgencyDirectory:
    return InMemoryAgencyDirectory()


@lru_cache(maxsize=1)
def get_user_store() -> SQLiteUserStore:
    return SQLiteUserStore(settings.IDENTITY_DB_PATH)


@lru_cache(maxsize=1)
def get_session_store() -> SQLiteSessionStore:
    return SQLiteSessionStore(settings.IDENTITY_DB_PATH)


@lru_cache(maxsize=1)
def get_password_hasher() -> ScryptPasswordHasher:
    return ScryptPasswordHasher()


@lru_cache(maxsize=1)
def get_identity_provider() -> LocalIdentityProvider:
    return LocalIdentityProvider(get_user_store(), get_password_hasher())


@lru_cache(maxsize=1)
def get_authentication_service() -> AuthenticationService:
    return AuthenticationService(
        identity_provider=get_identity_provider(),
        session_store=get_session_store(),
        event_store=get_event_store(),
        clearance_policy=get_security_policy().clearance,
        session_ttl_minutes=settings.SESSION_TTL_MINUTES,
    )


@lru_cache(maxsize=1)
def get_case_repository() -> SQLiteCaseRepository:
    return SQLiteCaseRepository(settings.INVESTIGATION_DB_PATH)


@lru_cache(maxsize=1)
def get_evidence_repository() -> SQLiteEvidenceRepository:
    return SQLiteEvidenceRepository(settings.INVESTIGATION_DB_PATH)


@lru_cache(maxsize=1)
def get_evidence_object_store() -> LocalFileEvidenceObjectStore:
    return LocalFileEvidenceObjectStore(settings.EVIDENCE_OBJECT_ROOT)


@lru_cache(maxsize=1)
def get_evidence_service() -> EvidenceService:
    return EvidenceService(
        repository=get_evidence_repository(),
        object_store=get_evidence_object_store(),
        security=get_security_service(),
        event_store=get_event_store(),
        privacy=get_security_policy().privacy,
        analyzers=(CdrSummaryAnalyzer(),),
    )


@lru_cache(maxsize=1)
def get_graph_repository() -> Neo4jGraphRepository:
    """Constructed eagerly, connected lazily: no Neo4j round-trip at startup."""
    return Neo4jGraphRepository(
        uri=settings.NEO4J_URI,
        user=settings.NEO4J_USER,
        password=settings.NEO4J_PASSWORD,
        database=settings.NEO4J_DATABASE,
    )


@lru_cache(maxsize=1)
def get_graph_service() -> GraphService:
    return GraphService(
        graph_repository=get_graph_repository(),
        evidence_repository=get_evidence_repository(),
        object_store=get_evidence_object_store(),
        security=get_security_service(),
        event_store=get_event_store(),
        privacy=get_security_policy().privacy,
    )


@lru_cache(maxsize=1)
def get_resolution_policy() -> ResolutionPolicy:
    return load_resolution_policy()


@lru_cache(maxsize=1)
def get_resolution_repository() -> SQLiteResolutionRepository:
    return SQLiteResolutionRepository(settings.INVESTIGATION_DB_PATH)


@lru_cache(maxsize=1)
def get_resolution_service() -> EntityResolutionService:
    return EntityResolutionService(
        resolution_repository=get_resolution_repository(),
        evidence_repository=get_evidence_repository(),
        object_store=get_evidence_object_store(),
        graph_repository=get_graph_repository(),
        security=get_security_service(),
        event_store=get_event_store(),
        policy=get_resolution_policy(),
        privacy=get_security_policy().privacy,
    )


@lru_cache(maxsize=1)
def get_analytics_policy() -> AnalyticsPolicy:
    return load_analytics_policy()


@lru_cache(maxsize=1)
def get_analytics_repository() -> SQLiteAnalyticsRepository:
    return SQLiteAnalyticsRepository(settings.INVESTIGATION_DB_PATH)


@lru_cache(maxsize=1)
def get_analytics_service() -> GraphAnalyticsService:
    return GraphAnalyticsService(
        graph_service=get_graph_service(),
        graph_repository=get_graph_repository(),
        analytics_repository=get_analytics_repository(),
        event_store=get_event_store(),
        policy=get_analytics_policy(),
    )


@lru_cache(maxsize=1)
def get_debt_policy() -> EvidenceDebtPolicy:
    return load_debt_policy()


@lru_cache(maxsize=1)
def get_debt_repository() -> SQLiteEvidenceDebtRepository:
    return SQLiteEvidenceDebtRepository(settings.INVESTIGATION_DB_PATH)


@lru_cache(maxsize=1)
def get_debt_service() -> EvidenceDebtService:
    return EvidenceDebtService(
        debt_repository=get_debt_repository(),
        evidence_repository=get_evidence_repository(),
        resolution_repository=get_resolution_repository(),
        analytics_repository=get_analytics_repository(),
        object_store=get_evidence_object_store(),
        security=get_security_service(),
        event_store=get_event_store(),
        policy=get_debt_policy(),
    )


@lru_cache(maxsize=1)
def get_security_service() -> SecurityService:
    policy = get_security_policy()
    return SecurityService(
        engine=ClearanceAuthorizationEngine(policy),
        grants=get_grant_repository(),
        event_store=get_event_store(),
        clearance_policy=policy.clearance,
    )


CACHED_PROVIDERS = (
    get_security_policy,
    get_event_store,
    get_grant_repository,
    get_agency_directory,
    get_user_store,
    get_session_store,
    get_password_hasher,
    get_identity_provider,
    get_authentication_service,
    get_security_service,
    get_case_repository,
    get_evidence_repository,
    get_evidence_object_store,
    get_evidence_service,
    get_graph_repository,
    get_graph_service,
    get_resolution_policy,
    get_resolution_repository,
    get_resolution_service,
    get_analytics_policy,
    get_analytics_repository,
    get_analytics_service,
    get_debt_policy,
    get_debt_repository,
    get_debt_service,
)


def reset_providers() -> None:
    """Drop every cached singleton. For process setup and tests, not request paths."""
    for provider in CACHED_PROVIDERS:
        provider.cache_clear()


def get_current_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    auth: AuthenticationService = Depends(get_authentication_service),
) -> Session:
    if credentials is None or not credentials.credentials:
        raise unauthorized(ApiError.SESSION_INVALID)
    try:
        return auth.resolve_session(credentials.credentials)
    except SessionExpired:
        raise unauthorized(ApiError.SESSION_EXPIRED) from None
    except SessionInvalid:
        raise unauthorized(ApiError.SESSION_INVALID) from None


def get_current_user(
    session: Session = Depends(get_current_session),
    auth: AuthenticationService = Depends(get_authentication_service),
) -> User:
    try:
        return auth.resolve_user(session)
    except SessionInvalid:
        raise unauthorized(ApiError.SESSION_INVALID) from None


def get_current_agency_context(
    session: Session = Depends(get_current_session),
    user: User = Depends(get_current_user),
    directory: InMemoryAgencyDirectory = Depends(get_agency_directory),
) -> AgencyContext | None:
    """Rebuild the active context from live user facts, or None if none is active.

    Role and clearance are read from the user store rather than the session row,
    so a revoked role or clearance applies on the next request.
    """
    if session.active_agency_id is None or user.clearance is None:
        return None
    agency = directory.get(session.active_agency_id)
    role = next((r for r in user.roles if r.id == session.active_role_id), None)
    if agency is None or role is None:
        return None
    return AgencyContext(
        agency=agency,
        user_id=user.id,
        role=role,
        clearance=user.clearance,
        department=session.active_department,
        unit=session.active_unit,
    )
