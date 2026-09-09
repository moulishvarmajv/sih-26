"""HTTP behaviour of the evidence-debt endpoints.

Authentication, agency context and case scope are swept for every route by
`test_security_regression.py`, which reads the route table from the running
application. What is checked here is what those sweeps cannot see: the shape of
the responses, that a GET leaves no state behind, and that nothing an L2 reader
receives carries an identifier or a gap they are not cleared for.

`dev.investigator` holds L2, so the restricted register in CASE-004 is out of
scope for every request in this module — which is exactly the reader the leak
tests need.
"""
import pytest

from app.core.audit.event_store import FlightRecorderEvent
from app.core.debt.models import DEBT_ENGINE_VERSION, DebtCategory
from tests.api_harness import build_api_harness
from tests.debt_case import CASE, OTHER_CASE, RESTRICTED_VALUES, build_debt_case

DEBT = f"/cases/{CASE.id}/evidence-debt"


@pytest.fixture
def wired(tmp_path, event_store, grants, policy):
    harness = build_api_harness(tmp_path, event_store, grants, policy)
    for case in (CASE, OTHER_CASE):
        harness.cases.create(case)
        grants.grant_case("USR-001", "POLICE", case.id, need_to_know=True)

    # Setup runs as a fully cleared operator so everything is recorded; the
    # tests below then read it as the L2 `dev.investigator`.
    from tests.conftest import make_context, make_user

    operator = make_user("USR-001", level="L3")
    context = make_context("USR-001", level="L3")
    harness.fixture = build_debt_case(
        evidence_service=harness.evidence_service,
        graph_service=harness.graph_service,
        resolution_service=harness.resolution_service,
        analytics_service=harness.analytics_service,
        evidence_repository=harness.evidence_repo,
        user=operator,
        context=context,
        tmp_path=tmp_path,
    )
    yield harness
    harness.close()


def get(wired, headers, path=""):
    return wired.client.get(f"{DEBT}{path}", headers=headers)


# -- the case-level view -----------------------------------------------------


def test_the_debt_endpoint_reports_a_total_a_band_and_a_breakdown(wired):
    headers = wired.authenticate()

    response = get(wired, headers)

    assert response.status_code == 200
    body = response.json()
    assert body["case_id"] == CASE.id
    assert body["total_debt"] > 0
    assert 0 <= body["normalized_debt"] <= 1
    assert body["band"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
    assert body["item_count"] > 0
    assert body["policy_version"]
    assert body["debt_engine_version"] == DEBT_ENGINE_VERSION
    assert len(body["breakdown"]) == len(DebtCategory)


def test_the_response_carries_the_scope_it_was_computed_over(wired):
    headers = wired.authenticate()

    body = get(wired, headers).json()

    assert body["evidence_in_scope"] == 5
    assert body["excluded_evidence_count"] == 1
    assert body["persisted"] is False


def test_a_read_records_nothing(wired):
    headers = wired.authenticate()

    get(wired, headers)
    get(wired, headers, "/items")

    assert wired.debt_repo.list_snapshots(CASE.id) == []
    assert wired.debt_repo.list_items(CASE.id) == []


def test_the_top_items_explain_themselves(wired):
    headers = wired.authenticate()

    top = get(wired, headers).json()["top_items"]

    assert top
    for item in top:
        assert item["category"] in {category.value for category in DebtCategory}
        assert item["severity"]
        assert item["reason"]
        assert item["subject"]["subject_type"]
        assert item["weighting"]["weighted_contribution"] > 0
        assert item["weighting"]["category_weight"] > 0
        assert item["blocking_reason"]


def test_the_breakdown_endpoint_reports_every_category(wired):
    headers = wired.authenticate()

    body = get(wired, headers, "/breakdown").json()

    assert [entry["category"] for entry in body["breakdown"]] == [
        category.value for category in DebtCategory
    ]
    assert body["total_debt"] > 0
    assert body["band"]


# -- items -------------------------------------------------------------------


def test_items_are_listed_ranked_and_actionable_where_they_are(wired):
    headers = wired.authenticate()

    body = get(wired, headers, "/items").json()

    assert body["item_count"] == len(body["items"])
    contributions = [item["weighting"]["weighted_contribution"] for item in body["items"]]
    assert contributions == sorted(contributions, reverse=True)
    assert [item["priority"] for item in body["items"]] == sorted(
        item["priority"] for item in body["items"]
    )
    actionable = [item for item in body["items"] if item["actionable"]]
    assert actionable
    assert all(item["required_capability"] for item in actionable)


def test_items_can_be_filtered_by_category(wired):
    headers = wired.authenticate()

    body = get(wired, headers, "/items?category=STALE").json()

    assert body["items"]
    assert {item["category"] for item in body["items"]} == {"STALE"}


def test_an_unknown_category_is_a_request_error_not_a_security_outcome(wired):
    headers = wired.authenticate()

    assert get(wired, headers, "/items?category=NOT_A_CATEGORY").status_code == 422


def test_one_item_can_be_read_with_its_history(wired):
    headers = wired.authenticate()
    debt_id = get(wired, headers, "/items").json()["items"][0]["debt_id"]

    response = get(wired, headers, f"/items/{debt_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["item"]["debt_id"] == debt_id
    assert body["item"]["supporting_evidence_ids"] is not None
    assert isinstance(body["history"], list)


def test_an_unknown_item_answers_as_an_unauthorized_one(wired):
    headers = wired.authenticate()

    response = get(wired, headers, "/items/DEBT-NOT-A-REAL-ID")

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "DEBT_ACCESS_DENIED"


def test_an_item_cannot_be_read_through_the_wrong_case(wired):
    headers = wired.authenticate()
    debt_id = get(wired, headers, "/items").json()["items"][0]["debt_id"]

    response = wired.client.get(
        f"/cases/{OTHER_CASE.id}/evidence-debt/items/{debt_id}", headers=headers
    )

    assert response.status_code == 403


# -- recalculation -----------------------------------------------------------


def test_recalculating_records_a_snapshot_and_its_items(wired):
    headers = wired.authenticate()

    response = wired.client.post(f"{DEBT}/recalculate", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["persisted"] is True
    assert wired.debt_repo.get_snapshot(body["snapshot_id"]) is not None
    assert wired.debt_repo.list_items(CASE.id)


def test_recalculating_twice_is_idempotent(wired):
    headers = wired.authenticate()

    first = wired.client.post(f"{DEBT}/recalculate", headers=headers).json()
    versions = {
        (item.debt_id, item.version) for item in wired.debt_repo.list_items(CASE.id)
    }
    second = wired.client.post(f"{DEBT}/recalculate", headers=headers).json()

    assert first["total_debt"] == second["total_debt"]
    assert sorted(first["breakdown"], key=lambda e: e["category"]) == sorted(
        second["breakdown"], key=lambda e: e["category"]
    )
    assert versions == {
        (item.debt_id, item.version) for item in wired.debt_repo.list_items(CASE.id)
    }


def test_the_trend_appears_once_there_is_something_to_compare_with(wired):
    headers = wired.authenticate()

    first = wired.client.post(f"{DEBT}/recalculate", headers=headers).json()
    assert first["change"]["previous_snapshot_id"] is None

    second = get(wired, headers).json()

    assert second["change"]["previous_snapshot_id"] == first["snapshot_id"]
    assert second["change"]["delta"] == 0
    assert second["change"]["unchanged_count"] == first["item_count"]


def test_an_analyst_may_read_but_not_recalculate(wired, grants):
    grants.grant_agency("USR-002", "POLICE")
    grants.grant_case("USR-002", "POLICE", CASE.id, need_to_know=True)
    headers = wired.authenticate("dev.analyst", agency_id="POLICE")

    assert get(wired, headers).status_code == 200
    assert wired.client.post(f"{DEBT}/recalculate", headers=headers).status_code == 403


# -- acknowledgement ---------------------------------------------------------


def test_an_item_can_be_acknowledged_and_stays_acknowledged(wired):
    headers = wired.authenticate()
    debt_id = get(wired, headers, "/items").json()["items"][0]["debt_id"]

    response = wired.client.post(
        f"{DEBT}/items/{debt_id}/acknowledge",
        json={"reason": "accepted pending the register"},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["item"]["status"] == "ACKNOWLEDGED"

    wired.client.post(f"{DEBT}/recalculate", headers=headers)
    after = get(wired, headers, f"/items/{debt_id}").json()["item"]
    assert after["status"] == "ACKNOWLEDGED"
    assert after["status_reason"] == "accepted pending the register"


def test_acknowledging_an_unknown_item_is_a_404(wired):
    headers = wired.authenticate()

    response = wired.client.post(f"{DEBT}/items/DEBT-ABSENT/acknowledge", headers=headers)

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "DEBT_ITEM_NOT_FOUND"


def test_an_analyst_cannot_acknowledge(wired, grants):
    """The role is checked before the item is looked up, so the answer is 403."""
    debt_id = get(wired, wired.authenticate(), "/items").json()["items"][0]["debt_id"]
    grants.grant_agency("USR-002", "POLICE")
    grants.grant_case("USR-002", "POLICE", CASE.id, need_to_know=True)
    analyst = wired.authenticate("dev.analyst", agency_id="POLICE")

    response = wired.client.post(f"{DEBT}/items/{debt_id}/acknowledge", headers=analyst)

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "DEBT_ACCESS_DENIED"


def test_a_reader_cleared_for_no_evidence_in_the_case_sees_no_debt(wired, grants):
    """Fail closed: every item in CASE-004 is above L1, so an L1 reader has none."""
    grants.grant_agency("USR-002", "POLICE")
    grants.grant_case("USR-002", "POLICE", CASE.id, need_to_know=True)
    headers = wired.authenticate("dev.analyst", agency_id="POLICE")

    body = get(wired, headers).json()

    assert body["total_debt"] == 0
    assert body["item_count"] == 0
    assert body["band"] == "LOW"
    assert body["evidence_in_scope"] == 0
    assert get(wired, headers, "/items").json()["items"] == []


# -- privacy and leakage -----------------------------------------------------


def test_no_restricted_value_appears_in_any_debt_response(wired):
    headers = wired.authenticate()
    wired.client.post(f"{DEBT}/recalculate", headers=headers)

    rendered = "".join(
        get(wired, headers, path).text
        for path in ("", "/breakdown", "/items")
    )

    for value in RESTRICTED_VALUES:
        assert value not in rendered


def test_no_debt_item_mentions_the_restricted_evidence(wired):
    headers = wired.authenticate()
    restricted_id = wired.fixture.restricted_evidence_id

    body = get(wired, headers, "/items").json()

    assert restricted_id not in body["items"][0]["supporting_evidence_ids"]
    assert restricted_id not in str(body)


def test_the_response_never_counts_what_it_omitted(wired):
    """A hidden conflict must leave no residue, not even a redacted counter."""
    headers = wired.authenticate()

    body = get(wired, headers).json()

    assert "hidden" not in str(body).lower()
    assert "redacted" not in str(body).lower()
    assert sum(entry["item_count"] for entry in body["breakdown"]) == body["item_count"]


def test_a_reader_in_another_agency_reaches_nothing(wired, grants):
    grants.grant_agency("USR-002", "FINANCIAL_CRIME")
    headers = wired.authenticate("dev.analyst", agency_id="FINANCIAL_CRIME")

    assert get(wired, headers).status_code == 403
    assert get(wired, headers, "/items").status_code == 403


# -- audit -------------------------------------------------------------------


def test_recalculating_over_http_is_audited(wired, event_store):
    headers = wired.authenticate()

    wired.client.post(f"{DEBT}/recalculate", headers=headers)

    recorded = {event.event_type for event in event_store.list_for_case(CASE.id)}
    assert FlightRecorderEvent.EVIDENCE_DEBT_CALCULATION_STARTED in recorded
    assert FlightRecorderEvent.EVIDENCE_DEBT_CALCULATION_COMPLETED in recorded


def test_a_denied_debt_read_over_http_is_audited(wired, grants, event_store):
    grants.grant_agency("USR-002", "POLICE")
    headers = wired.authenticate("dev.analyst", agency_id="POLICE")

    get(wired, headers)

    denied = [
        event
        for event in event_store.list_for_case(CASE.id)
        if event.event_type is FlightRecorderEvent.EVIDENCE_DEBT_ACCESS_DENIED
    ]
    assert denied
