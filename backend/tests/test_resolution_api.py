"""HTTP behaviour of the entity-resolution endpoints.

What these hold the boundary to: authentication, an active agency context, case
scope, and the rule that a response never carries an identifier the reader's
evidence decision redacted — including the identifiers that did the matching.
"""
import pytest

from app.core.audit.event_store import FlightRecorderEvent
from app.core.domain.case import Case
from app.core.resolution.policy import load_resolution_policy
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from app.infrastructure.sources.synthetic_subscriber import SyntheticSubscriberRegisterSource
from tests.api_harness import PASSWORD, build_api_harness

CASE = Case(
    id="CASE-001", agency_id="POLICE", title="Resolution case", status="OPEN", security_level="L1"
)
OTHER_CASE = Case(
    id="CASE-002", agency_id="POLICE", title="Second case", status="OPEN", security_level="L1"
)

#: Raw identifiers that appear in the synthetic data. None of them may reach a
#: reader whose evidence decision redacted them, however they got there.
RESTRICTED_VALUES = (
    "919876543210",
    "919900112233",
    "356938035643809",
    "404450123456789",
    "ACC-88213",
    "NID-SYNTH-12A",
    "Ananya Sharma",
)


@pytest.fixture
def wired(tmp_path, event_store, grants, policy):
    harness = build_api_harness(tmp_path, event_store, grants, policy)
    for case in (CASE, OTHER_CASE):
        harness.cases.create(case)
        harness.evidence_service.ingest_from_source(case, SyntheticCDRSource())
        harness.evidence_service.ingest_from_source(
            case, SyntheticSubscriberRegisterSource()
        )
    # USR-001 works CASE-001 only, so case isolation is testable through the API.
    grants.grant_case("USR-001", "POLICE", CASE.id, need_to_know=True)

    client = harness.client
    client.harness = harness
    client.graph_repo = harness.graph_repo
    client.grants = grants
    yield client
    harness.close()


def authenticate(client, username="dev.investigator"):
    return client.harness.authenticate(username)


def run(client, headers, case_id=CASE.id):
    return client.post(f"/cases/{case_id}/entity-resolution/run", headers=headers)


def open_resolution_id(client, headers):
    body = client.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()
    return next(
        item["resolution_id"]
        for item in body["resolutions"]
        if item["status"] == "REVIEW_REQUIRED"
    )


# -- authentication and context ---------------------------------------------


def test_every_endpoint_requires_authentication(wired):
    resolution_id = "ER-ANY-v1"
    responses = [
        wired.post(f"/cases/{CASE.id}/entity-resolution/run"),
        wired.get(f"/cases/{CASE.id}/entity-resolution"),
        wired.get(f"/cases/{CASE.id}/entity-resolution/{resolution_id}"),
        wired.post(f"/cases/{CASE.id}/entity-resolution/{resolution_id}/approve"),
        wired.post(f"/cases/{CASE.id}/entity-resolution/{resolution_id}/reject"),
    ]

    assert [response.status_code for response in responses] == [401] * 5
    assert all(
        response.json()["detail"] == {"error": "SESSION_INVALID"} for response in responses
    )


def test_resolution_requires_an_active_agency_context(wired):
    token = wired.post(
        "/auth/login", json={"username": "dev.investigator", "password": PASSWORD}
    ).json()["token"]

    response = run(wired, {"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "NO_ACTIVE_CONTEXT"}


# -- running -----------------------------------------------------------------


def test_a_run_returns_what_it_decided(wired):
    headers = authenticate(wired)

    body = run(wired, headers).json()

    assert body["case_id"] == CASE.id
    assert body["policy_version"] == load_resolution_policy().policy_version
    assert body["candidates"] == 4
    assert body["auto_accepted"] == 1
    assert body["review_required"] == 3


def test_reading_resolutions_does_not_create_any(wired):
    headers = authenticate(wired)

    body = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()

    assert body["resolutions"] == []


def test_re_running_is_idempotent(wired):
    headers = authenticate(wired)
    run(wired, headers)
    first = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()

    second_run = run(wired, headers).json()
    second = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()

    assert second_run["unchanged"] == second_run["candidates"]
    assert second_run["auto_accepted"] == 0
    assert first == second


# -- explainability ----------------------------------------------------------


def test_a_resolution_explains_itself(wired):
    headers = authenticate(wired)
    run(wired, headers)

    body = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()
    accepted = next(
        item for item in body["resolutions"] if item["status"] == "AUTO_ACCEPTED"
    )

    explanation = accepted["explanation"]
    assert explanation["recommendation"] == "MATCH"
    assert explanation["confidence"] in {"LOW", "MEDIUM", "HIGH"}
    assert explanation["score"] >= explanation["confidence_floor"]
    assert explanation["policy_version"] == load_resolution_policy().policy_version
    assert "EXACT_PHONE_MATCH" in explanation["reasons"]
    assert explanation["conflicts"] == []
    assert {item["signal"] for item in explanation["evidence"]} >= {
        "EXACT_PHONE",
        "NAME_SIMILARITY",
        "TEMPORAL_CONSISTENCY",
    }


def test_a_resolution_says_why_the_pair_was_compared(wired):
    headers = authenticate(wired)
    run(wired, headers)

    body = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()

    origin = body["resolutions"][0]["candidate"]
    assert origin["blocking_strategy"] in {
        "EXACT_PHONE",
        "EXACT_IMEI",
        "EXACT_ACCOUNT",
        "SOURCE_IDENTIFIER",
        "NAME_LOCALITY",
    }
    assert origin["blocking_key_attribute"]


def test_every_resolution_is_labelled_inferred(wired):
    headers = authenticate(wired)
    run(wired, headers)

    body = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()

    assert body["resolutions"]
    assert {item["trust_class"] for item in body["resolutions"]} == {"INFERRED"}


def test_a_conflict_is_reported_as_a_conflict(wired):
    headers = authenticate(wired)
    run(wired, headers)

    body = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()
    conflicted = [
        item for item in body["resolutions"] if item["explanation"]["conflicts"]
    ]

    assert conflicted
    conflict = conflicted[0]["explanation"]["conflicts"][0]
    assert conflict["rule"]
    assert isinstance(conflict["blocks_auto_accept"], bool)
    assert conflicted[0]["status"] != "AUTO_ACCEPTED"


# -- privacy -----------------------------------------------------------------


def test_no_restricted_identifier_reaches_a_partial_reader(wired):
    """dev.investigator holds L2; the privacy policy unmasks only at L3."""
    headers = authenticate(wired)
    run(wired, headers)

    body = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).text

    for value in RESTRICTED_VALUES:
        assert value not in body


def test_matching_identifiers_are_named_but_never_disclosed(wired):
    headers = authenticate(wired)
    run(wired, headers)

    body = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()

    evidence = body["resolutions"][0]["explanation"]["evidence"]
    assert {item["attribute"] for item in evidence} >= {"phone", "imei"}
    assert all(not str(item["attribute"]).isdigit() for item in evidence)


def test_a_masked_entity_still_has_a_usable_identity(wired):
    headers = authenticate(wired)
    run(wired, headers)

    body = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()

    refs = {item["left"]["entity_ref"] for item in body["resolutions"]}
    refs |= {item["right"]["entity_ref"] for item in body["resolutions"]}
    assert len(refs) > 1
    assert all(ref.startswith("person:") for ref in refs)
    assert "entity_key" in body["resolutions"][0]["masked_fields"]


def test_the_blocking_value_itself_is_never_returned(wired):
    """A pair blocked on a phone number must not hand that number back.

    The response names the attribute the pair blocked on and stops there: the
    value is a raw identifier, and it is withheld at every clearance level
    rather than masked at some of them.
    """
    headers = authenticate(wired)
    run(wired, headers)

    body = wired.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).json()

    blocked_on_a_phone = [
        item
        for item in body["resolutions"]
        if item["candidate"]["blocking_strategy"] == "EXACT_PHONE"
    ]
    assert blocked_on_a_phone
    for item in body["resolutions"]:
        assert set(item["candidate"]) == {
            "candidate_id",
            "blocking_strategy",
            "blocking_key_attribute",
            "created_at",
        }
        assert item["candidate"]["blocking_key_attribute"] == "phone"


# -- case scope --------------------------------------------------------------


def test_an_unknown_case_is_indistinguishable_from_a_denied_one(wired):
    headers = authenticate(wired)

    assert run(wired, headers, "CASE-404").status_code == 403
    assert wired.get("/cases/CASE-404/entity-resolution", headers=headers).json()[
        "detail"
    ] == {"error": "CASE_ACCESS_DENIED"}


def test_a_case_the_reader_has_no_grant_for_is_denied(wired):
    headers = authenticate(wired)

    response = run(wired, headers, OTHER_CASE.id)

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "RESOLUTION_ACCESS_DENIED"}


def test_a_resolution_cannot_be_read_through_the_wrong_case(wired):
    headers = authenticate(wired)
    run(wired, headers)
    resolution_id = open_resolution_id(wired, headers)

    wired.grants.grant_case("USR-001", "POLICE", OTHER_CASE.id, need_to_know=True)
    response = wired.get(
        f"/cases/{OTHER_CASE.id}/entity-resolution/{resolution_id}", headers=headers
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "RESOLUTION_ACCESS_DENIED"}


def test_an_unknown_resolution_id_leaks_nothing(wired):
    headers = authenticate(wired)
    run(wired, headers)

    response = wired.get(
        f"/cases/{CASE.id}/entity-resolution/ER-DOES-NOT-EXIST-v1", headers=headers
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "RESOLUTION_ACCESS_DENIED"}


# -- review ------------------------------------------------------------------


def test_approving_through_the_api_records_a_human_decision(wired):
    headers = authenticate(wired)
    run(wired, headers)
    resolution_id = open_resolution_id(wired, headers)

    response = wired.post(
        f"/cases/{CASE.id}/entity-resolution/{resolution_id}/approve",
        json={"reason": "confirmed with the registrar"},
        headers=headers,
    )

    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "APPROVED"
    assert body["decision_actor"] == "HUMAN"
    assert body["decided_by"] == "USR-001"
    assert body["reviews"][-1]["action"] == "APPROVE"


def test_rejecting_through_the_api_records_a_human_decision(wired):
    headers = authenticate(wired)
    run(wired, headers)
    resolution_id = open_resolution_id(wired, headers)

    body = wired.post(
        f"/cases/{CASE.id}/entity-resolution/{resolution_id}/reject", headers=headers
    ).json()

    assert body["status"] == "REJECTED"
    assert body["decision_actor"] == "HUMAN"


def test_deferring_keeps_the_resolution_in_the_queue(wired):
    headers = authenticate(wired)
    run(wired, headers)
    resolution_id = open_resolution_id(wired, headers)

    body = wired.post(
        f"/cases/{CASE.id}/entity-resolution/{resolution_id}/defer",
        json={"reason": "pending confirmation"},
        headers=headers,
    ).json()

    assert body["status"] == "REVIEW_REQUIRED"
    assert body["reviews"][-1]["action"] == "DEFER"
    assert body["reviews"][-1]["reason"] == "pending confirmation"


def test_a_decided_resolution_cannot_be_decided_twice(wired):
    headers = authenticate(wired)
    run(wired, headers)
    resolution_id = open_resolution_id(wired, headers)
    wired.post(f"/cases/{CASE.id}/entity-resolution/{resolution_id}/approve", headers=headers)

    response = wired.post(
        f"/cases/{CASE.id}/entity-resolution/{resolution_id}/reject", headers=headers
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "RESOLUTION_NOT_OPEN"}


def test_a_role_without_review_permission_is_refused(wired, grants):
    """dev.analyst may run and read resolutions but may not rule on one."""
    headers = authenticate(wired)
    run(wired, headers)
    resolution_id = open_resolution_id(wired, headers)

    grants.grant_agency("USR-002", "POLICE")
    grants.grant_case("USR-002", "POLICE", CASE.id, need_to_know=True)
    analyst = authenticate(wired, username="dev.analyst")
    response = wired.post(
        f"/cases/{CASE.id}/entity-resolution/{resolution_id}/approve", headers=analyst
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "RESOLUTION_ACCESS_DENIED"}


def test_approval_writes_the_inferred_link(wired):
    headers = authenticate(wired)
    run(wired, headers)
    before = len(wired.graph_repo.fetch_inferred_links(CASE.id))
    resolution_id = open_resolution_id(wired, headers)

    wired.post(f"/cases/{CASE.id}/entity-resolution/{resolution_id}/approve", headers=headers)

    links = wired.graph_repo.fetch_inferred_links(CASE.id)
    assert len(links) == before + 1
    assert any(link.properties["resolution_id"] == resolution_id for link in links)
    assert all(link.properties["trust_class"] == "INFERRED" for link in links)


# -- audit -------------------------------------------------------------------


def test_api_activity_is_audited_with_the_acting_user(wired, event_store):
    headers = authenticate(wired)
    run(wired, headers)

    started = event_store.list_by_type(FlightRecorderEvent.ENTITY_RESOLUTION_STARTED)
    assert len(started) == 1
    assert started[0].actor_id == "USR-001"
    assert started[0].case_id == CASE.id


def test_a_denied_api_call_is_audited(wired, event_store):
    headers = authenticate(wired)

    run(wired, headers, OTHER_CASE.id)

    denied = event_store.list_by_type(FlightRecorderEvent.ENTITY_RESOLUTION_ACCESS_DENIED)
    assert denied
    assert denied[0].case_id == OTHER_CASE.id


# -- availability ------------------------------------------------------------


def test_the_rest_of_the_application_is_unaffected_by_resolution(wired):
    headers = authenticate(wired)
    run(wired, headers)

    assert wired.get("/health").status_code == 200
    assert wired.get("/me", headers=headers).status_code == 200
    assert wired.get(f"/cases/{CASE.id}/evidence", headers=headers).status_code == 200


def test_a_run_still_succeeds_when_the_graph_is_down(wired):
    headers = authenticate(wired)
    wired.graph_repo._available = False

    response = run(wired, headers)

    body = response.json()
    assert response.status_code == 200
    assert body["graph_available"] is False
    assert body["links_projected"] == 0
    assert body["auto_accepted"] == 1
