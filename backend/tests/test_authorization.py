"""Authorization decisions: clearance is necessary but never sufficient."""
from app.core.domain.authorization import AuthorizationEffect, PrivacyAction, ReasonCode
from app.core.domain.identity import Role
from tests.conftest import (
    ANALYST,
    FINANCIAL_CRIME,
    POLICE,
    make_case,
    make_context,
    make_evidence,
    make_user,
)


def authorized_user(grants, *, level="L2", case_id="CASE-001", agency=POLICE):
    """A user granted the agency, the case and need-to-know — clearance is the only variable left."""
    user = make_user(level=level)
    grants.grant_agency(user.id, agency.id)
    grants.grant_case(user.id, agency.id, case_id, need_to_know=True)
    return user


def test_l1_user_may_read_l1_evidence(security, grants):
    user = authorized_user(grants, level="L1")
    case = make_case(security_level="L1")
    evidence = make_evidence(security_level="L1")

    decision = security.authorize_evidence_access(
        user, make_context(level="L1"), case, evidence
    )

    assert decision.effect is AuthorizationEffect.ALLOW
    assert decision.reason is ReasonCode.ACCESS_GRANTED


def test_l1_user_may_not_read_l2_evidence(security, grants):
    user = authorized_user(grants, level="L1")
    case = make_case(security_level="L1")
    evidence = make_evidence(security_level="L2")

    decision = security.authorize_evidence_access(
        user, make_context(level="L1"), case, evidence
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.reason is ReasonCode.CLEARANCE_INSUFFICIENT
    assert decision.user_clearance == "L1"
    assert decision.required_clearance == "L2"


def test_l2_user_may_read_l2_evidence_when_case_and_need_to_know_pass(security, grants):
    user = authorized_user(grants, level="L2")

    decision = security.authorize_evidence_access(
        user, make_context(level="L2"), make_case(), make_evidence(security_level="L2")
    )

    assert decision.effect is AuthorizationEffect.ALLOW
    assert decision.case_allowed is True
    assert decision.need_to_know is True


def test_l2_user_may_not_read_l3_evidence(security, grants):
    user = authorized_user(grants, level="L2")

    decision = security.authorize_evidence_access(
        user, make_context(level="L2"), make_case(), make_evidence(security_level="L3")
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.reason is ReasonCode.CLEARANCE_INSUFFICIENT


def test_evidence_without_declared_level_falls_back_to_fail_closed_default(security, grants, policy):
    user = authorized_user(grants, level="L2")

    decision = security.authorize_evidence_access(
        user, make_context(level="L2"), make_case(), make_evidence(security_level=None)
    )

    assert decision.required_clearance == policy.clearance.default_required_level
    assert decision.effect is AuthorizationEffect.DENY


def test_sufficient_clearance_without_case_access_is_denied(security, grants):
    user = make_user(level="L3")
    grants.grant_agency(user.id, POLICE.id)  # agency granted, case is not

    decision = security.authorize_evidence_access(
        user, make_context(level="L3"), make_case(), make_evidence(security_level="L1")
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.reason is ReasonCode.CASE_ACCESS_DENIED
    assert decision.case_allowed is False


def test_sufficient_clearance_without_agency_access_is_denied(security, grants):
    user = make_user(level="L3")  # no agency grant at all

    decision = security.authorize_case_access(user, make_context(level="L3"), make_case())

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.reason is ReasonCode.AGENCY_ACCESS_DENIED
    assert decision.agency_allowed is False


def test_case_access_without_need_to_know_is_denied(security, grants):
    user = make_user(level="L3")
    grants.grant_agency(user.id, POLICE.id)
    grants.grant_case(user.id, POLICE.id, "CASE-001", need_to_know=False)

    decision = security.authorize_case_access(user, make_context(level="L3"), make_case())

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.reason is ReasonCode.NEED_TO_KNOW_DENIED


def test_context_may_not_claim_more_clearance_than_the_user_holds(security, grants):
    user = authorized_user(grants, level="L1")

    decision = security.authorize_evidence_access(
        user, make_context(level="L3"), make_case(), make_evidence(security_level="L3")
    )

    assert decision.effect is AuthorizationEffect.DENY
    assert decision.reason is ReasonCode.CONTEXT_CLEARANCE_ESCALATION


def test_expired_clearance_is_denied(security, grants):
    user = make_user(level="L3", expires_at="2020-01-01T00:00:00+00:00")
    grants.grant_agency(user.id, POLICE.id)
    grants.grant_case(user.id, POLICE.id, "CASE-001")

    decision = security.authorize_case_access(user, make_context(level="L3"), make_case())

    assert decision.reason is ReasonCode.CLEARANCE_EXPIRED


def test_context_belonging_to_another_user_is_denied(security, grants):
    user = authorized_user(grants, level="L2")

    decision = security.authorize_case_access(
        user, make_context(user_id="USR-999", level="L2"), make_case()
    )

    assert decision.reason is ReasonCode.IDENTITY_CONTEXT_MISMATCH


def test_case_from_another_agency_is_denied(security, grants):
    user = authorized_user(grants, level="L2")

    decision = security.authorize_case_access(
        user, make_context(level="L2"), make_case(agency_id="FINANCIAL_CRIME")
    )

    assert decision.reason is ReasonCode.CASE_AGENCY_MISMATCH


def test_evidence_from_another_case_is_denied(security, grants):
    user = authorized_user(grants, level="L2")

    decision = security.authorize_evidence_access(
        user, make_context(level="L2"), make_case(), make_evidence(case_id="CASE-777")
    )

    assert decision.reason is ReasonCode.EVIDENCE_CASE_MISMATCH


def test_role_without_the_action_is_denied(security, grants):
    user = authorized_user(grants, level="L2")
    read_only = Role(id="ROLE-CLERK", name="CLERK", permissions=("VIEW_CASE",))

    decision = security.authorize_evidence_access(
        user, make_context(level="L2", role=read_only), make_case(), make_evidence()
    )

    assert decision.reason is ReasonCode.ROLE_ACTION_DENIED


def test_privacy_policy_downgrades_allow_to_partial(security, grants):
    user = authorized_user(grants, level="L2")
    evidence = make_evidence(
        security_level="L2", sensitive_fields=("subscriber_name", "tower_id")
    )

    decision = security.authorize_evidence_access(
        user, make_context(level="L2"), make_case(), evidence
    )

    assert decision.effect is AuthorizationEffect.PARTIAL
    assert decision.reason is ReasonCode.PRIVACY_MASK_APPLIED
    assert decision.privacy_action is PrivacyAction.MASK
    assert decision.redacted_fields == ("subscriber_name",)


def test_clearance_above_unmask_threshold_sees_unmasked(security, grants):
    user = authorized_user(grants, level="L3")
    evidence = make_evidence(security_level="L2", sensitive_fields=("subscriber_name",))

    decision = security.authorize_evidence_access(
        user, make_context(level="L3"), make_case(), evidence
    )

    assert decision.effect is AuthorizationEffect.ALLOW
    assert decision.redacted_fields == ()


def test_agency_context_switch_is_re_evaluated_per_context(security, grants):
    user = make_user(level="L2")
    grants.grant_agency(user.id, POLICE.id)

    police = security.authorize_agency_context(user, make_context(level="L2", agency=POLICE))
    financial = security.authorize_agency_context(
        user, make_context(level="L2", agency=FINANCIAL_CRIME, role=ANALYST)
    )

    assert police.effect is AuthorizationEffect.ALLOW
    assert financial.effect is AuthorizationEffect.DENY
    assert financial.reason is ReasonCode.AGENCY_ACCESS_DENIED


def test_repeated_identical_checks_are_deterministic(security, grants):
    user = authorized_user(grants, level="L2")
    context, case, evidence = make_context(level="L2"), make_case(), make_evidence()

    decisions = [
        security.authorize_evidence_access(user, context, case, evidence) for _ in range(5)
    ]

    assert {(d.effect, d.reason, d.redacted_fields) for d in decisions} == {
        (decisions[0].effect, decisions[0].reason, decisions[0].redacted_fields)
    }


def test_denial_carries_no_resource_content(security, grants):
    user = authorized_user(grants, level="L1")

    decision = security.authorize_evidence_access(
        user, make_context(level="L1"), make_case(), make_evidence(security_level="L3")
    )
    payload = decision.to_audit_payload()

    assert decision.is_denied
    assert set(payload) == {
        "decision",
        "reason",
        "user_id",
        "agency",
        "action",
        "case_id",
        "evidence_id",
        "user_clearance",
        "required_clearance",
        "agency_allowed",
        "case_allowed",
        "need_to_know",
        "privacy_action",
        "redacted_fields",
    }
