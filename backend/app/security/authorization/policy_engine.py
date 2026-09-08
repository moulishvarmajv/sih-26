"""Clearance/agency/case/need-to-know authorization engine.

Pure policy: no storage, no network, no clock beyond the timestamp handed in.
Checks run in a fixed order so a given (request, facts) pair always yields the
same effect and reason code.

Clearance is never sufficient on its own — it is checked *after* agency, case,
need-to-know and role, and a satisfied clearance still yields PARTIAL when the
privacy policy requires masking.
"""
from __future__ import annotations

from app.core.domain.authorization import (
    AuthorizationDecision,
    AuthorizationEffect,
    PrivacyAction,
    ReasonCode,
)
from app.security.authorization.models import AuthorizationFacts, AuthorizationRequest
from app.security.policy.loader import SecurityPolicy


class ClearanceAuthorizationEngine:
    def __init__(self, policy: SecurityPolicy) -> None:
        self._policy = policy

    def evaluate(
        self, request: AuthorizationRequest, facts: AuthorizationFacts
    ) -> AuthorizationDecision:
        clearance = self._policy.clearance
        required = clearance.required_or_default(facts.required_clearance)

        def decide(
            effect: AuthorizationEffect,
            reason: ReasonCode,
            *,
            privacy_action: PrivacyAction = PrivacyAction.NONE,
            redacted_fields: tuple[str, ...] = (),
        ) -> AuthorizationDecision:
            return AuthorizationDecision(
                effect=effect,
                reason=reason,
                user_id=request.user_id,
                agency_id=request.agency_id,
                action=request.action,
                timestamp=request.timestamp,
                correlation_id=request.correlation_id,
                case_id=request.case_id,
                evidence_id=request.evidence_id,
                user_clearance=facts.user_clearance,
                required_clearance=required,
                agency_allowed=facts.agency_allowed,
                case_allowed=facts.case_allowed,
                need_to_know=facts.need_to_know,
                privacy_action=privacy_action,
                redacted_fields=redacted_fields,
            )

        def deny(reason: ReasonCode) -> AuthorizationDecision:
            return decide(AuthorizationEffect.DENY, reason)

        if not facts.identity_matches_context:
            return deny(ReasonCode.IDENTITY_CONTEXT_MISMATCH)
        if facts.user_clearance is None:
            return deny(ReasonCode.CLEARANCE_MISSING)
        if not clearance.knows(facts.user_clearance) or not clearance.knows(required):
            return deny(ReasonCode.CLEARANCE_LEVEL_UNKNOWN)
        if facts.clearance_expired:
            return deny(ReasonCode.CLEARANCE_EXPIRED)
        if facts.context_clearance_escalated:
            return deny(ReasonCode.CONTEXT_CLEARANCE_ESCALATION)
        if not facts.agency_allowed:
            return deny(ReasonCode.AGENCY_ACCESS_DENIED)
        if facts.case_belongs_to_agency is False:
            return deny(ReasonCode.CASE_AGENCY_MISMATCH)
        if facts.case_allowed is False:
            return deny(ReasonCode.CASE_ACCESS_DENIED)
        if facts.evidence_belongs_to_case is False:
            return deny(ReasonCode.EVIDENCE_CASE_MISMATCH)
        if facts.need_to_know is False:
            return deny(ReasonCode.NEED_TO_KNOW_DENIED)
        if not facts.role_permits_action:
            return deny(ReasonCode.ROLE_ACTION_DENIED)
        if not clearance.satisfies(facts.user_clearance, required):
            return deny(ReasonCode.CLEARANCE_INSUFFICIENT)

        masked = self._masked_fields(facts.user_clearance, facts.sensitive_fields)
        if masked:
            return decide(
                AuthorizationEffect.PARTIAL,
                ReasonCode.PRIVACY_MASK_APPLIED,
                privacy_action=PrivacyAction.MASK,
                redacted_fields=masked,
            )
        return decide(AuthorizationEffect.ALLOW, ReasonCode.ACCESS_GRANTED)

    def _masked_fields(self, user_clearance: str, sensitive_fields: tuple[str, ...]) -> tuple[str, ...]:
        privacy = self._policy.privacy
        clearance = self._policy.clearance
        if not sensitive_fields:
            return ()
        unmask_level = privacy.unmask_minimum_level
        if clearance.knows(unmask_level) and clearance.satisfies(user_clearance, unmask_level):
            return ()
        return privacy.fields_to_mask(sensitive_fields)
