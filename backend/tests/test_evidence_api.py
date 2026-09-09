"""HTTP behaviour of the protected evidence endpoints."""
import json

import pytest

from app.core.audit.event_store import FlightRecorderEvent
from app.core.domain.case import Case
from app.core.domain.identity import Clearance
from app.infrastructure.clock import utc_now_iso
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from tests.api_harness import PASSWORD, build_api_harness

CASE = Case(id="CASE-001", agency_id="POLICE", title="Synthetic case", status="OPEN", security_level="L1")


@pytest.fixture
def wired(tmp_path, event_store, grants, policy):
    harness = build_api_harness(tmp_path, event_store, grants, policy)
    harness.cases.create(CASE)
    harness.evidence_service.ingest_from_source(CASE, SyntheticCDRSource())
    # USR-001 is an L2 investigator seeded with POLICE access; give it the case.
    grants.grant_case("USR-001", "POLICE", CASE.id, need_to_know=True)

    client = harness.client
    client.harness = harness
    client.evidence_repo = harness.evidence_repo
    client.user_store = harness.user_store
    client.hasher = harness.hasher
    yield client
    harness.close()


def authenticate(client, username="dev.investigator"):
    """Log in and select the POLICE context, returning ready-to-use headers."""
    return client.harness.authenticate(username)


def first_evidence_id(client, headers):
    return client.get(f"/cases/{CASE.id}/evidence", headers=headers).json()["evidence"][0][
        "evidence_id"
    ]


def test_evidence_endpoints_require_authentication(wired):
    for method, path in [
        ("get", f"/cases/{CASE.id}/evidence"),
        ("get", "/evidence/EV-1?case_id=CASE-001"),
        ("get", "/evidence/EV-1/versions?case_id=CASE-001"),
        ("get", "/evidence/EV-1/analysis?case_id=CASE-001"),
        ("post", "/evidence/EV-1/analyze?case_id=CASE-001"),
        ("post", "/evidence/EV-1/reanalyze?case_id=CASE-001"),
    ]:
        response = getattr(wired, method)(path)
        assert response.status_code == 401, path
        assert response.json()["detail"] == {"error": "SESSION_INVALID"}


def test_evidence_requires_an_active_agency_context(wired):
    token = wired.post(
        "/auth/login", json={"username": "dev.investigator", "password": PASSWORD}
    ).json()["token"]

    response = wired.get(
        f"/cases/{CASE.id}/evidence", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "NO_ACTIVE_CONTEXT"}


def test_list_case_evidence(wired):
    headers = authenticate(wired)

    response = wired.get(f"/cases/{CASE.id}/evidence", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body["evidence"]) == 2
    assert body["evidence"][0]["classification"] == "OBSERVED"
    assert body["evidence"][0]["state"] == "AVAILABLE"


def test_view_masks_payload_for_partial_authorization(wired):
    """USR-001 holds L2; the CDR identifiers require L3 to see unmasked."""
    headers = authenticate(wired)
    evidence_id = first_evidence_id(wired, headers)

    response = wired.get(f"/evidence/{evidence_id}?case_id={CASE.id}", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "PARTIAL"
    assert set(body["masked_fields"]) == {"caller", "callee", "imei", "imsi"}
    row = body["payload"]["records"][0]
    assert row["caller"] == "+91-XXXX-3210"
    assert row["imei"] == "***"
    assert "+919876543210" not in json.dumps(body)


def test_unauthorized_case_returns_a_safe_denial_without_payload(wired):
    """dev.analyst has no POLICE grant, so it cannot even select the context."""
    token = wired.post(
        "/auth/login", json={"username": "dev.analyst", "password": PASSWORD}
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    switch = wired.post("/context/switch", json={"agency_id": "POLICE"}, headers=headers)

    response = wired.get(f"/cases/{CASE.id}/evidence", headers=headers)

    assert switch.status_code == 403
    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "NO_ACTIVE_CONTEXT"}
    assert "records" not in response.text


def test_unknown_case_and_evidence_are_indistinguishable_from_denied(wired):
    headers = authenticate(wired)

    unknown_case = wired.get("/cases/CASE-999/evidence", headers=headers)
    unknown_evidence = wired.get(f"/evidence/EV-NOPE?case_id={CASE.id}", headers=headers)

    assert unknown_case.status_code == 403
    assert unknown_case.json()["detail"] == {"error": "CASE_ACCESS_DENIED"}
    assert unknown_evidence.status_code == 403
    assert unknown_evidence.json()["detail"] == {"error": "EVIDENCE_ACCESS_DENIED"}


def test_versions_endpoint_lists_versions(wired):
    headers = authenticate(wired)
    evidence_id = first_evidence_id(wired, headers)

    response = wired.get(f"/evidence/{evidence_id}/versions?case_id={CASE.id}", headers=headers)

    assert response.status_code == 200
    versions = response.json()["versions"]
    assert len(versions) == 1
    assert versions[0]["version_number"] == 1
    assert versions[0]["state"] == "CURRENT"
    assert len(versions[0]["content_hash"]) == 64


def test_reading_analysis_before_it_exists_does_not_process(wired):
    headers = authenticate(wired)
    evidence_id = first_evidence_id(wired, headers)

    response = wired.get(f"/evidence/{evidence_id}/analysis?case_id={CASE.id}", headers=headers)

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "ANALYSIS_NOT_AVAILABLE"}
    assert wired.evidence_repo.list_runs(evidence_id) == []


def test_analyze_then_view_reuses_the_result(wired):
    headers = authenticate(wired)
    evidence_id = first_evidence_id(wired, headers)

    first = wired.post(f"/evidence/{evidence_id}/analyze?case_id={CASE.id}", headers=headers)
    second = wired.post(f"/evidence/{evidence_id}/analyze?case_id={CASE.id}", headers=headers)
    read_back = wired.get(f"/evidence/{evidence_id}/analysis?case_id={CASE.id}", headers=headers)

    assert first.status_code == 200
    assert first.json()["reused"] is False
    assert first.json()["classification"] == "DERIVED"
    assert second.json()["reused"] is True
    assert second.json()["result_id"] == first.json()["result_id"]
    assert read_back.json()["result_id"] == first.json()["result_id"]
    assert len(wired.evidence_repo.list_runs(evidence_id)) == 1


def test_reanalyze_creates_a_new_run(wired, event_store):
    headers = authenticate(wired)
    evidence_id = first_evidence_id(wired, headers)
    first = wired.post(f"/evidence/{evidence_id}/analyze?case_id={CASE.id}", headers=headers)

    second = wired.post(f"/evidence/{evidence_id}/reanalyze?case_id={CASE.id}", headers=headers)

    assert second.status_code == 200
    assert second.json()["run_id"] != first.json()["run_id"]
    assert len(wired.evidence_repo.list_runs(evidence_id)) == 2
    assert len(event_store.list_by_type(FlightRecorderEvent.EVIDENCE_REANALYZED)) == 1


def test_role_without_reanalyze_permission_is_denied(wired, grants):
    """An ANALYST holds ANALYZE but not REANALYZE; the role check must bite.

    Given clearance and case access equal to the investigator's, the role is the
    only difference left, so a denial here can only come from the role check.
    """
    wired.user_store.create_account(
        user_id="USR-010",
        username="dev.analyst.l2",
        password_hash=wired.hasher.hash(PASSWORD),
        display_name="Dev Analyst L2",
        clearance=Clearance(level_code="L2", granted_by="TEST", granted_at=utc_now_iso()),
        role_ids=("ROLE-ANALYST",),
    )
    grants.grant_agency("USR-010", "POLICE")
    grants.grant_case("USR-010", "POLICE", CASE.id, need_to_know=True)
    headers = authenticate(wired, username="dev.analyst.l2")
    evidence_id = first_evidence_id(wired, headers)

    allowed = wired.post(f"/evidence/{evidence_id}/analyze?case_id={CASE.id}", headers=headers)
    denied = wired.post(f"/evidence/{evidence_id}/reanalyze?case_id={CASE.id}", headers=headers)

    assert allowed.status_code == 200
    assert denied.status_code == 403
    assert denied.json()["detail"] == {"error": "EVIDENCE_ACCESS_DENIED"}


def test_endpoints_ignore_client_supplied_identity(wired, event_store):
    """A client cannot act as another user by asking to."""
    headers = authenticate(wired)
    evidence_id = first_evidence_id(wired, headers)

    response = wired.get(
        f"/evidence/{evidence_id}?case_id={CASE.id}&user_id=USR-999",
        headers={**headers, "X-User-Id": "USR-999"},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "PARTIAL"  # still USR-001's own L2 decision
    viewed = event_store.list_by_type(FlightRecorderEvent.EVIDENCE_VIEWED)
    assert {event.actor_id for event in viewed} == {"USR-001"}
    assert event_store.list_for_user("USR-999") == []


def test_every_view_is_audited(wired, event_store):
    headers = authenticate(wired)
    evidence_id = first_evidence_id(wired, headers)

    wired.get(f"/evidence/{evidence_id}?case_id={CASE.id}", headers=headers)
    wired.get(f"/evidence/{evidence_id}?case_id={CASE.id}", headers=headers)

    viewed = event_store.list_by_type(FlightRecorderEvent.EVIDENCE_VIEWED)
    assert len(viewed) == 2
    assert {event.actor_id for event in viewed} == {"USR-001"}
    assert len(event_store.list_by_type(FlightRecorderEvent.EVIDENCE_REDACTED)) == 2
