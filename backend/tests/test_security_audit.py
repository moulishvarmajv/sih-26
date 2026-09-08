"""Every authorization outcome reaches the flight recorder."""
from app.core.audit.event_store import ActorType, FlightRecorderEvent
from tests.conftest import POLICE, make_case, make_context, make_evidence, make_user


def granted_user(grants, level="L2"):
    user = make_user(level=level)
    grants.grant_agency(user.id, POLICE.id)
    grants.grant_case(user.id, POLICE.id, "CASE-001", need_to_know=True)
    return user


def test_allowed_evidence_access_is_audited(security, grants, event_store):
    user = granted_user(grants)

    security.authorize_evidence_access(
        user, make_context(level="L2"), make_case(), make_evidence(security_level="L2")
    )

    events = event_store.list_by_type(FlightRecorderEvent.EVIDENCE_ACCESS_ALLOWED)
    assert len(events) == 1
    assert events[0].actor_id == user.id
    assert events[0].actor_type is ActorType.USER
    assert events[0].case_id == "CASE-001"
    assert events[0].payload["decision"] == "ALLOW"
    assert events[0].payload["evidence_id"] == "EV-309"


def test_denied_evidence_access_is_audited_with_reason(security, grants, event_store):
    user = granted_user(grants, level="L1")

    security.authorize_evidence_access(
        user, make_context(level="L1"), make_case(security_level="L1"), make_evidence("EV-777")
    )

    events = event_store.list_by_type(FlightRecorderEvent.EVIDENCE_ACCESS_DENIED)
    assert len(events) == 1
    assert events[0].payload["reason"] == "CLEARANCE_INSUFFICIENT"
    assert events[0].payload["user_clearance"] == "L1"
    assert events[0].payload["required_clearance"] == "L2"


def test_partial_access_is_audited_as_redaction(security, grants, event_store):
    user = granted_user(grants)
    evidence = make_evidence(security_level="L2", sensitive_fields=("subscriber_name",))

    security.authorize_evidence_access(user, make_context(level="L2"), make_case(), evidence)

    events = event_store.list_by_type(FlightRecorderEvent.EVIDENCE_REDACTED)
    assert len(events) == 1
    assert events[0].payload["redacted_fields"] == ["subscriber_name"]
    assert events[0].payload["privacy_action"] == "MASK"


def test_case_access_outcomes_are_audited(security, grants, event_store):
    allowed = granted_user(grants)
    denied = make_user(user_id="USR-900", level="L3")

    security.authorize_case_access(allowed, make_context(level="L2"), make_case())
    security.authorize_case_access(
        denied, make_context(user_id="USR-900", level="L3"), make_case()
    )

    assert len(event_store.list_by_type(FlightRecorderEvent.CASE_ACCESS_ALLOWED)) == 1
    assert len(event_store.list_by_type(FlightRecorderEvent.CASE_ACCESS_DENIED)) == 1


def test_agency_context_outcomes_are_audited(security, grants, event_store):
    user = granted_user(grants)

    security.authorize_agency_context(user, make_context(level="L2"))
    security.authorize_agency_context(user, make_context(user_id="USR-999", level="L2"))

    assert len(event_store.list_by_type(FlightRecorderEvent.AGENCY_CONTEXT_SWITCHED)) == 1
    assert len(event_store.list_by_type(FlightRecorderEvent.AGENCY_CONTEXT_DENIED)) == 1


def test_case_history_is_ordered_and_scoped(security, grants, event_store):
    user = granted_user(grants)
    context = make_context(level="L2")

    security.authorize_case_access(user, context, make_case())
    security.authorize_evidence_access(user, context, make_case(), make_evidence())
    security.authorize_agency_context(user, context)  # no case scope

    history = event_store.list_for_case("CASE-001")

    assert [event.event_type for event in history] == [
        FlightRecorderEvent.CASE_ACCESS_ALLOWED,
        FlightRecorderEvent.EVIDENCE_ACCESS_ALLOWED,
    ]
    assert [event.sequence for event in history] == sorted(event.sequence for event in history)


def test_correlation_id_is_propagated_to_the_audit_trail(security, grants, event_store):
    user = granted_user(grants)

    security.authorize_case_access(
        user, make_context(level="L2"), make_case(), correlation_id="corr-abc"
    )

    assert event_store.list_for_user(user.id)[0].correlation_id == "corr-abc"
