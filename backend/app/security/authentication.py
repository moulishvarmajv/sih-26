"""Authentication service: credentials in, authenticated session out.

Strictly "who is this?". It never decides what the principal may do — that stays
with SecurityService/AuthorizationEngine. Login therefore succeeds even when a
clearance grant is stale; the session simply carries no verified clearance, and
the authorization engine denies protected work on its own terms.

Every attempt is audited: LOGIN / LOGIN_FAILED, plus CLEARANCE_VERIFIED when the
grant checks out. Audit payloads carry no credential material.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Callable

from app.core.audit.event_store import ActorType, EventDraft, EventStore, FlightRecorderEvent
from app.core.domain.identity import User
from app.infrastructure.clock import parse_iso, utc_now_iso
from app.infrastructure.logging import current_correlation_id
from app.security.clearance.policy import ClearancePolicy
from app.security.clearance.verification import ClearanceState, verify_clearance
from app.security.identity.models import AuthenticationOutcome, Credentials
from app.security.identity.provider import IdentityProvider
from app.security.session.models import AuthenticationMethod, Session, SessionStatus
from app.security.session.store import SessionStore


@dataclass(frozen=True)
class LoginResult:
    token: str
    session: Session
    user: User
    clearance_state: ClearanceState

    @property
    def clearance_verified(self) -> bool:
        return self.clearance_state is ClearanceState.VALID


class AuthenticationError(Exception):
    """Raised when credentials cannot be resolved to an authenticated principal."""


class SessionInvalid(Exception):
    """Raised when a bearer token does not resolve to a usable session."""


class SessionExpired(Exception):
    """Raised when a session exists but has passed its expiry."""


class AuthenticationService:
    def __init__(
        self,
        identity_provider: IdentityProvider,
        session_store: SessionStore,
        event_store: EventStore,
        clearance_policy: ClearancePolicy,
        session_ttl_minutes: int,
        clock: Callable[[], str] = utc_now_iso,
    ) -> None:
        self._identity = identity_provider
        self._sessions = session_store
        self._events = event_store
        self._clearance = clearance_policy
        self._ttl_minutes = session_ttl_minutes
        self._clock = clock

    def login(self, credentials: Credentials, *, correlation_id: str | None = None) -> LoginResult:
        correlation = correlation_id or current_correlation_id()
        result = self._identity.authenticate(credentials)

        if not result.succeeded or result.user is None:
            self._record(
                FlightRecorderEvent.LOGIN_FAILED,
                actor_id=None,
                correlation_id=correlation,
                payload={
                    "outcome": result.outcome.value,
                    "authentication_method": AuthenticationMethod.LOCAL_PASSWORD.value,
                },
            )
            raise AuthenticationError(result.outcome.value)

        user = result.user
        now = self._clock()
        issued = self._sessions.create(
            user_id=user.id,
            created_at=now,
            expires_at=(parse_iso(now) + timedelta(minutes=self._ttl_minutes)).isoformat(),
            authentication_method=AuthenticationMethod.LOCAL_PASSWORD,
            correlation_id=correlation,
        )

        self._record(
            FlightRecorderEvent.LOGIN,
            actor_id=user.id,
            correlation_id=correlation,
            payload={
                "session_id": issued.session.session_id,
                "authentication_method": issued.session.authentication_method.value,
                "expires_at": issued.session.expires_at,
            },
        )

        state = verify_clearance(user.clearance, self._clearance, now)
        if state is ClearanceState.VALID and user.clearance is not None:
            self._record(
                FlightRecorderEvent.CLEARANCE_VERIFIED,
                actor_id=user.id,
                correlation_id=correlation,
                payload={
                    "session_id": issued.session.session_id,
                    "clearance_level": user.clearance.level_code,
                    "expires_at": user.clearance.expires_at,
                },
            )

        return LoginResult(
            token=issued.token, session=issued.session, user=user, clearance_state=state
        )

    def resolve_session(self, token: str) -> Session:
        """Return the session for a bearer token, or raise if it is unusable."""
        session = self._sessions.get_by_token(token)
        if session is None:
            raise SessionInvalid("SESSION_INVALID")
        if session.status is not SessionStatus.ACTIVE:
            raise SessionInvalid("SESSION_INVALID")
        if parse_iso(session.expires_at) <= parse_iso(self._clock()):
            self._sessions.mark_expired(session.session_id)
            raise SessionExpired("SESSION_EXPIRED")
        return session

    def resolve_user(self, session: Session) -> User:
        user = self._identity.get_user(session.user_id)
        if user is None:
            raise SessionInvalid("SESSION_INVALID")
        return user

    def _record(
        self,
        event_type: FlightRecorderEvent,
        *,
        actor_id: str | None,
        correlation_id: str,
        payload: dict,
    ) -> None:
        self._events.append(
            EventDraft(
                event_type=event_type,
                actor_id=actor_id,
                actor_type=ActorType.USER,
                correlation_id=correlation_id,
                payload=payload,
            )
        )
