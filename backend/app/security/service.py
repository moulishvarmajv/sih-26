"""Security service: the boundary API routes call instead of evaluating policy themselves.

Responsibilities, kept separate on purpose:
  - repositories resolve *facts* (grants, need-to-know)
  - the engine turns facts into an AuthorizationDecision (pure policy)
  - this service sequences the two and records the outcome to the flight recorder

Every authorization outcome — allow, partial and deny — is audited. Decisions
carry no resource content, so audit payloads never leak what was denied.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Callable

from app.core.audit.event_store import ActorType, EventDraft, EventStore, FlightRecorderEvent
from app.core.domain.agency import AgencyContext
from app.core.domain.authorization import AuthorizationDecision, AuthorizationEffect
from app.core.domain.case import Case
from app.core.domain.identity import Clearance, User
from app.core.evidence.models import EvidenceRecord
from app.infrastructure.clock import utc_now_iso
from app.infrastructure.logging import current_correlation_id
from app.security.authorization.engine import AuthorizationEngine
from app.security.authorization.models import AuthorizationFacts, AuthorizationRequest
from app.security.clearance.policy import ClearancePolicy
from app.security.clearance.verification import is_expired
from app.security.grants import AccessGrantRepository
from app.security.roles.permissions import role_permits

ACTION_SWITCH_CONTEXT = "SWITCH_AGENCY_CONTEXT"
ACTION_VIEW_CASE = "VIEW_CASE"
ACTION_VIEW_EVIDENCE = "VIEW_EVIDENCE"

_EVENTS_BY_EFFECT: dict[str, dict[AuthorizationEffect, FlightRecorderEvent]] = {
    "agency_context": {
        AuthorizationEffect.ALLOW: FlightRecorderEvent.AGENCY_CONTEXT_SWITCHED,
        AuthorizationEffect.PARTIAL: FlightRecorderEvent.AGENCY_CONTEXT_SWITCHED,
        AuthorizationEffect.DENY: FlightRecorderEvent.AGENCY_CONTEXT_DENIED,
    },
    "case": {
        AuthorizationEffect.ALLOW: FlightRecorderEvent.CASE_ACCESS_ALLOWED,
        AuthorizationEffect.PARTIAL: FlightRecorderEvent.CASE_ACCESS_ALLOWED,
        AuthorizationEffect.DENY: FlightRecorderEvent.CASE_ACCESS_DENIED,
    },
    "evidence": {
        AuthorizationEffect.ALLOW: FlightRecorderEvent.EVIDENCE_ACCESS_ALLOWED,
        AuthorizationEffect.PARTIAL: FlightRecorderEvent.EVIDENCE_REDACTED,
        AuthorizationEffect.DENY: FlightRecorderEvent.EVIDENCE_ACCESS_DENIED,
    },
    "action": {
        AuthorizationEffect.ALLOW: FlightRecorderEvent.ACTION_ALLOWED,
        AuthorizationEffect.PARTIAL: FlightRecorderEvent.ACTION_ALLOWED,
        AuthorizationEffect.DENY: FlightRecorderEvent.ACTION_DENIED,
    },
}


class SecurityService:
    def __init__(
        self,
        engine: AuthorizationEngine,
        grants: AccessGrantRepository,
        event_store: EventStore,
        clearance_policy: ClearancePolicy,
        clock: Callable[[], str] = utc_now_iso,
    ) -> None:
        self._engine = engine
        self._grants = grants
        self._event_store = event_store
        self._clearance = clearance_policy
        self._clock = clock

    def authorize_agency_context(
        self, user: User, context: AgencyContext, *, correlation_id: str | None = None
    ) -> AuthorizationDecision:
        """Evaluate whether a user may operate in the agency context they are claiming."""
        request = self._request(
            user, context, ACTION_SWITCH_CONTEXT, correlation_id=correlation_id
        )
        facts = self._base_facts(user, context, ACTION_SWITCH_CONTEXT)
        return self._decide("agency_context", request, facts)

    def authorize_case_access(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        action: str = ACTION_VIEW_CASE,
        *,
        correlation_id: str | None = None,
    ) -> AuthorizationDecision:
        request = self._request(
            user, context, action, case_id=case.id, correlation_id=correlation_id
        )
        facts = self._case_facts(user, context, case, action)
        return self._decide("case", request, facts)

    def authorize_evidence_access(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        evidence: EvidenceRecord,
        action: str = ACTION_VIEW_EVIDENCE,
        *,
        correlation_id: str | None = None,
    ) -> AuthorizationDecision:
        request = self._request(
            user,
            context,
            action,
            case_id=case.id,
            evidence_id=evidence.id,
            correlation_id=correlation_id,
        )
        case_facts = self._case_facts(user, context, case, action)
        facts = replace(
            case_facts,
            required_clearance=evidence.security_level,
            evidence_belongs_to_case=evidence.case_id == case.id,
            sensitive_fields=evidence.sensitive_fields,
        )
        return self._decide("evidence", request, facts)

    def authorize_action(
        self,
        user: User,
        context: AgencyContext,
        action: str,
        *,
        case: Case | None = None,
        required_clearance: str | None = None,
        resource_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthorizationDecision:
        """Generic entry point for actions that are not case- or evidence-shaped."""
        request = self._request(
            user,
            context,
            action,
            case_id=case.id if case else None,
            evidence_id=resource_id,
            correlation_id=correlation_id,
        )
        facts = (
            self._case_facts(user, context, case, action)
            if case is not None
            else self._base_facts(user, context, action)
        )
        if required_clearance is not None:
            facts = replace(facts, required_clearance=required_clearance)
        return self._decide("action", request, facts)

    def _request(
        self,
        user: User,
        context: AgencyContext,
        action: str,
        *,
        case_id: str | None = None,
        evidence_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthorizationRequest:
        return AuthorizationRequest(
            user_id=user.id,
            agency_id=context.agency.id,
            action=action,
            correlation_id=correlation_id or current_correlation_id(),
            timestamp=self._clock(),
            case_id=case_id,
            evidence_id=evidence_id,
        )

    def _base_facts(self, user: User, context: AgencyContext, action: str) -> AuthorizationFacts:
        held = user.clearance.level_code if user.clearance else None
        claimed = context.clearance.level_code
        return AuthorizationFacts(
            identity_matches_context=context.user_id == user.id,
            agency_allowed=context.agency.id in self._grants.agencies_for_user(user.id),
            role_permits_action=role_permits(context.role, action),
            user_clearance=claimed,
            clearance_expired=self._is_expired(user.clearance),
            context_clearance_escalated=self._is_escalated(held, claimed),
            required_clearance=claimed,
        )

    def _case_facts(
        self, user: User, context: AgencyContext, case: Case, action: str
    ) -> AuthorizationFacts:
        granted_cases = self._grants.cases_for_user(user.id, context.agency.id)
        return replace(
            self._base_facts(user, context, action),
            required_clearance=case.security_level,
            case_belongs_to_agency=case.agency_id == context.agency.id,
            case_allowed=case.id in granted_cases,
            need_to_know=self._grants.has_need_to_know(user.id, case.id),
        )

    def _is_expired(self, clearance: Clearance | None) -> bool:
        return is_expired(clearance, self._clock())

    def _is_escalated(self, held: str | None, claimed: str) -> bool:
        if held is None:
            return True
        if not self._clearance.knows(held) or not self._clearance.knows(claimed):
            return True
        return not self._clearance.satisfies(held, claimed)

    def _decide(
        self, kind: str, request: AuthorizationRequest, facts: AuthorizationFacts
    ) -> AuthorizationDecision:
        decision = self._engine.evaluate(request, facts)
        self._event_store.append(
            EventDraft(
                event_type=_EVENTS_BY_EFFECT[kind][decision.effect],
                actor_id=decision.user_id,
                actor_type=ActorType.USER,
                correlation_id=decision.correlation_id,
                case_id=decision.case_id,
                payload=decision.to_audit_payload(),
            )
        )
        return decision
