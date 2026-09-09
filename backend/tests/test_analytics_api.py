"""HTTP behaviour of the analytics and signal endpoints.

Authentication, agency context and case scope are swept for every route by
`test_security_regression.py`, which reads the route table from the running
application. What is checked here is what those sweeps cannot see: the shape of
the responses, that a GET leaves no state behind, and that nothing an L2 reader
receives carries an identifier they are not cleared for.
"""
import pytest

from app.core.audit.event_store import FlightRecorderEvent
from app.core.domain.case import Case
from app.core.graph.models import NodeLabel, node_ref_id
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from tests.api_harness import build_api_harness

CASE = Case(
    id="CASE-003", agency_id="POLICE", title="Analytics case", status="OPEN", security_level="L1"
)

GROUP_A1, GROUP_A3 = "919820100001", "919820100003"
GROUP_B1 = "919730200001"
BRIDGE = "919810300001"
HELPLINE = "911800111222"
RESTRICTED = "919000500001"

#: In the synthetic data. dev.investigator holds L2, and the privacy policy
#: unmasks at L3, so none of these may appear in any response.
RESTRICTED_VALUES = (
    GROUP_A1, GROUP_B1, BRIDGE, HELPLINE, RESTRICTED,
    "351111111111111", "404450111111111",
)


def phone(msisdn: str) -> str:
    return node_ref_id(NodeLabel.PHONE, msisdn)


@pytest.fixture
def wired(tmp_path, event_store, grants, policy):
    harness = build_api_harness(tmp_path, event_store, grants, policy)
    harness.cases.create(CASE)
    harness.evidence_service.ingest_from_source(CASE, SyntheticCDRSource())
    harness.graph_service.ingest_case_evidence(CASE)
    grants.grant_case("USR-001", "POLICE", CASE.id, need_to_know=True)
    yield harness
    harness.close()


def overview(wired, headers):
    return wired.client.get(f"/cases/{CASE.id}/analytics/overview", headers=headers)


# -- overview ----------------------------------------------------------------


def test_the_overview_describes_the_case_structure(wired):
    headers = wired.authenticate()

    body = overview(wired, headers).json()

    assert body["case_id"] == CASE.id
    assert body["analytics_version"]
    assert body["entity_count"] > 0
    assert len(body["components"]) == 2
    assert body["top_connectivity"]
    assert body["bridges"]
    assert body["temporal_concentrations"]


def test_connectivity_is_ranked_and_explained(wired):
    headers = wired.authenticate()

    top = overview(wired, headers).json()["top_connectivity"][0]

    assert top["rank"] == 1
    assert top["degree"] >= 1
    assert top["rank_of"] >= top["rank"]
    assert top["supporting_relationship_ids"]
    assert top["supporting_evidence_ids"]


def test_a_bridge_explains_what_it_holds_apart(wired):
    headers = wired.authenticate()

    bridge = overview(wired, headers).json()["bridges"][0]

    assert bridge["groups_separated"] >= 2
    assert len(bridge["group_sizes"]) == bridge["groups_separated"]
    assert bridge["separated_side_size"] >= 1
    assert bridge["supporting_evidence_ids"]


def test_a_temporal_concentration_reports_its_window(wired):
    headers = wired.authenticate()

    window = overview(wired, headers).json()["temporal_concentrations"][0]

    assert window["window_start"] < window["window_end"]
    assert window["event_count"] >= 3
    assert window["concentration_ratio"] > 1.0
    assert window["supporting_relationship_ids"]


def test_the_overview_reports_what_it_could_not_see(wired):
    headers = wired.authenticate()

    body = overview(wired, headers).json()

    assert body["excluded_evidence_count"] == 1  # the restricted export
    assert body["truncated"] is False
    assert "msisdn" in body["masked_properties"]


# -- entity and path ---------------------------------------------------------


def test_entity_analytics_describe_one_entity(wired):
    headers = wired.authenticate()

    body = wired.client.get(
        f"/cases/{CASE.id}/analytics/entity/{phone(BRIDGE)}", headers=headers
    ).json()

    assert body["entity"]["entity_id"] == phone(BRIDGE)
    assert body["connectivity"]["degree"] > 0
    assert body["bridge"] is not None
    assert body["component_id"]
    assert body["neighbours"]


def test_a_path_is_returned_with_its_steps_and_provenance(wired):
    headers = wired.authenticate()

    body = wired.client.get(
        f"/cases/{CASE.id}/analytics/path/{phone(GROUP_A1)}/{phone(GROUP_B1)}",
        headers=headers,
    ).json()

    assert body["found"] is True
    assert body["reason"] == "PATH_FOUND"
    assert body["length"] == len(body["steps"]) >= 1
    assert len(body["entities"]) == body["length"] + 1
    assert body["supporting_evidence_ids"]
    assert all(step["relationship_id"] for step in body["steps"])


def test_no_path_is_reported_plainly(wired):
    headers = wired.authenticate()

    body = wired.client.get(
        f"/cases/{CASE.id}/analytics/path/{phone(GROUP_A1)}/{phone(HELPLINE)}",
        headers=headers,
    ).json()

    assert body["found"] is False
    assert body["steps"] == []
    assert body["reason"] == "NO_PATH_WITHIN_LIMIT"
    assert body["max_length_searched"] >= 1


def test_an_unknown_entity_answers_not_found(wired):
    headers = wired.authenticate()

    response = wired.client.get(
        f"/cases/{CASE.id}/analytics/entity/phone:nosuchentity", headers=headers
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "ANALYTICS_ENTITY_NOT_FOUND"}


def test_a_restricted_entity_answers_exactly_like_an_absent_one(wired):
    """Telling them apart would confirm the entity exists."""
    headers = wired.authenticate()

    restricted = wired.client.get(
        f"/cases/{CASE.id}/analytics/entity/{phone(RESTRICTED)}", headers=headers
    )
    absent = wired.client.get(
        f"/cases/{CASE.id}/analytics/entity/phone:nosuchentity", headers=headers
    )

    assert restricted.status_code == absent.status_code == 404
    assert restricted.json() == absent.json()


# -- privacy -----------------------------------------------------------------


def test_no_restricted_identifier_reaches_a_partial_reader(wired):
    headers = wired.authenticate()
    wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=headers)

    bodies = [
        overview(wired, headers).text,
        wired.client.get(
            f"/cases/{CASE.id}/analytics/entity/{phone(BRIDGE)}", headers=headers
        ).text,
        wired.client.get(
            f"/cases/{CASE.id}/analytics/path/{phone(GROUP_A1)}/{phone(GROUP_B1)}",
            headers=headers,
        ).text,
        wired.client.get(f"/cases/{CASE.id}/signals", headers=headers).text,
    ]

    for body in bodies:
        for value in RESTRICTED_VALUES:
            assert value not in body


def test_a_masked_entity_still_has_a_usable_identity(wired):
    headers = wired.authenticate()

    entities = overview(wired, headers).json()["top_connectivity"]

    refs = {metric["entity"]["entity_id"] for metric in entities}
    assert len(refs) == len(entities)
    assert all(":" in ref for ref in refs)


# -- run and signals ---------------------------------------------------------


def test_reading_analytics_records_nothing(wired):
    headers = wired.authenticate()

    overview(wired, headers)

    assert wired.client.get(f"/cases/{CASE.id}/signals", headers=headers).json()["signals"] == []


def test_a_run_records_signals(wired):
    headers = wired.authenticate()

    run = wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=headers).json()

    assert run["signal_count"] > 0
    assert run["analytics_version"]
    assert run["evidence_in_scope"] >= 1
    assert run["excluded_evidence_count"] == 1
    signals = wired.client.get(f"/cases/{CASE.id}/signals", headers=headers).json()["signals"]
    assert len(signals) == run["signal_count"]


def test_a_signal_explains_itself(wired):
    headers = wired.authenticate()
    wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=headers)

    signals = wired.client.get(f"/cases/{CASE.id}/signals", headers=headers).json()["signals"]
    ranked = next(s for s in signals if s["signal_type"] == "CROSS_DOMAIN_BRIDGE")

    assert ranked["reasons"]
    assert ranked["confidence"] in {"LOW", "MEDIUM", "HIGH"}
    assert ranked["analytics_version"]
    assert ranked["metrics"]
    for metric in ranked["metrics"]:
        assert metric["weight"] >= 0
        assert 0.0 <= metric["normalized"] <= 1.0
    assert ranked["supporting_evidence_ids"]


def test_signals_can_be_filtered_by_type(wired):
    headers = wired.authenticate()
    wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=headers)

    body = wired.client.get(
        f"/cases/{CASE.id}/signals?signal_type=TEMPORAL_CONCENTRATION", headers=headers
    ).json()

    assert body["signals"]
    assert {s["signal_type"] for s in body["signals"]} == {"TEMPORAL_CONCENTRATION"}


def test_an_unknown_signal_type_is_a_request_error(wired):
    headers = wired.authenticate()

    response = wired.client.get(
        f"/cases/{CASE.id}/signals?signal_type=NOT_A_TYPE", headers=headers
    )

    assert response.status_code == 422


def test_one_signal_can_be_read_by_id(wired):
    headers = wired.authenticate()
    wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=headers)
    signal_id = wired.client.get(f"/cases/{CASE.id}/signals", headers=headers).json()[
        "signals"
    ][0]["signal_id"]

    body = wired.client.get(f"/cases/{CASE.id}/signals/{signal_id}", headers=headers).json()

    assert body["signal_id"] == signal_id
    assert body["status"] == "ACTIVE"
    assert body["version"] == 1


def test_an_unknown_signal_id_leaks_nothing(wired):
    headers = wired.authenticate()

    response = wired.client.get(f"/cases/{CASE.id}/signals/SIG-NOPE", headers=headers)

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "ANALYTICS_ACCESS_DENIED"}


def test_re_running_keeps_one_active_signal_per_identity(wired):
    headers = wired.authenticate()
    wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=headers)
    first = wired.client.get(f"/cases/{CASE.id}/signals", headers=headers).json()["signals"]

    wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=headers)
    second = wired.client.get(f"/cases/{CASE.id}/signals", headers=headers).json()["signals"]

    assert len(first) == len(second)
    assert {s["signal_id"] for s in first} == {s["signal_id"] for s in second}
    assert {s["version"] for s in second} == {2}


# -- authorization and audit -------------------------------------------------


def test_a_reader_below_the_evidence_clearance_gets_no_analytics(wired, grants):
    """dev.analyst holds L1; every evidence item in this case is L2 or above.

    With nothing in scope there is no authorized graph to analyse, so both
    reading and running are refused — the fail-closed outcome, not an empty
    result set. The narrower question of *permission* (an L2 analyst may read
    analytics but not record signals) is pinned down at service level, where the
    clearance can be held constant.
    """
    grants.grant_agency("USR-002", "POLICE")
    grants.grant_case("USR-002", "POLICE", CASE.id, need_to_know=True)
    analyst = wired.authenticate("dev.analyst")

    read = wired.client.get(f"/cases/{CASE.id}/analytics/overview", headers=analyst)
    run = wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=analyst)

    assert read.status_code == run.status_code == 403
    assert run.json()["detail"] == {"error": "ANALYTICS_ACCESS_DENIED"}
    assert "9198" not in read.text


def test_api_activity_is_audited_with_the_acting_user(wired, event_store):
    headers = wired.authenticate()

    wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=headers)

    started = event_store.list_by_type(FlightRecorderEvent.ANALYTICS_STARTED)
    assert started
    assert started[0].actor_id == "USR-001"
    assert started[0].case_id == CASE.id


def test_the_rest_of_the_application_is_unaffected(wired):
    headers = wired.authenticate()
    wired.client.post(f"/cases/{CASE.id}/analytics/run", headers=headers)

    assert wired.client.get("/health").status_code == 200
    assert wired.client.get("/me", headers=headers).status_code == 200
    assert wired.client.get(f"/cases/{CASE.id}/evidence", headers=headers).status_code == 200
    assert wired.client.get(f"/cases/{CASE.id}/graph", headers=headers).status_code == 200
