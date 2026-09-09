"""The whole pipeline, over HTTP, against a real Neo4j.

Every other suite substitutes something: the API suites use an in-memory graph,
the integration suites drive the repository directly. This one puts the real
graph behind the real application and walks the path an investigator walks —

    ingest -> project to the graph -> read it under authorization
           -> resolve entities -> project the inference -> review it

— asserting the security properties at each step rather than afterwards. It is
the test that would notice a wiring mistake no single-layer suite can see.

Skipped unless a server is reachable. Writes under a case id unique to the run
and removes exactly what it wrote.
"""
import uuid

import pytest

from app.core.domain.case import Case
from app.core.graph.models import RelationshipType
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from app.infrastructure.sources.synthetic_subscriber import SyntheticSubscriberRegisterSource
from tests.api_harness import build_api_harness
from tests.neo4j_support import SKIP_REASON, build_repository, cleanup, server_is_reachable

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not server_is_reachable(), reason=SKIP_REASON),
]

#: Identifiers in the synthetic data. The reader below holds L2, and the privacy
#: policy unmasks at L3, so none of these may appear in any response.
RESTRICTED_VALUES = ("919876543210", "356938035643809", "404450123456789", "Ananya Sharma")


@pytest.fixture
def case_id():
    return f"CASE-E2E-{uuid.uuid4().hex[:8].upper()}"


@pytest.fixture
def live(tmp_path, event_store, grants, policy, case_id):
    """The real application, with the real graph behind it."""
    graph = build_repository()
    harness = build_api_harness(tmp_path, event_store, grants, policy, graph_repository=graph)

    case = Case(
        id=case_id,
        agency_id="POLICE",
        title="End-to-end case",
        status="OPEN",
        security_level="L1",
    )
    harness.cases.create(case)
    # The shipped datasets are keyed to CASE-001; retarget them at this run.
    for source in (SyntheticCDRSource(), SyntheticSubscriberRegisterSource()):
        for item in list(source.fetch("CASE-001")):
            harness.evidence_service.ingest_from_source(case, _OneShotSource(source, item))
    grants.grant_case("USR-001", "POLICE", case.id, need_to_know=True)

    harness.case = case
    yield harness
    harness.close()
    cleanup(graph, case_id)
    graph.close()


class _OneShotSource:
    """Replays one record from a shipped dataset under this run's case id."""

    def __init__(self, source, item):
        self.source_id = source.source_id
        self._item = item

    def fetch(self, case_id):
        return [self._item]


def test_the_pipeline_runs_end_to_end_under_authorization(live):
    client, case = live.client, live.case
    headers = live.authenticate()

    # 1. Evidence is listed only for a reader who holds the case.
    listing = client.get(f"/cases/{case.id}/evidence", headers=headers)
    assert listing.status_code == 200
    assert len(listing.json()["evidence"]) == 3

    # 2. Ingestion projects observations into the real graph.
    summary = live.graph_service.ingest_case_evidence(case)
    assert summary.evidence_processed == 2  # two CDR exports
    assert summary.evidence_skipped == 1  # the register has no graph mapper
    assert summary.relationships_written > 0

    # 3. The authorized graph read returns observations, masked for L2.
    graph = client.get(f"/cases/{case.id}/graph", headers=headers)
    assert graph.status_code == 200
    body = graph.json()
    assert {node["label"] for node in body["nodes"]} >= {"Phone", "Device", "Person"}
    assert "msisdn" in body["masked_properties"]
    assert all(
        relationship["provenance"]["trust_class"] == "OBSERVED"
        for relationship in body["relationships"]
        if relationship["provenance"]
    )

    # 4. Resolution is an explicit step and writes an inference, not an observation.
    run = client.post(f"/cases/{case.id}/entity-resolution/run", headers=headers)
    assert run.status_code == 200
    assert run.json()["graph_available"] is True
    assert run.json()["auto_accepted"] == 1
    assert run.json()["links_projected"] == 1

    # 5. The inferred link is in Neo4j, marked INFERRED, naming both sources.
    links = live.graph_repo.fetch_inferred_links(case.id)
    assert len(links) == 1
    assert links[0].type is RelationshipType.INFERRED_SAME_ENTITY
    assert links[0].properties["trust_class"] == "INFERRED"
    assert len(links[0].properties["source_evidence_version_ids"]) == 2

    # 6. It is not returned as an observation.
    reread = client.get(f"/cases/{case.id}/graph", headers=headers).json()
    assert all(
        relationship["type"] != "INFERRED_SAME_ENTITY"
        for relationship in reread["relationships"]
    )

    # 7. A human decision closes an open resolution and is recorded as human.
    open_id = next(
        item["resolution_id"]
        for item in client.get(
            f"/cases/{case.id}/entity-resolution", headers=headers
        ).json()["resolutions"]
        if item["status"] == "REVIEW_REQUIRED"
    )
    approved = client.post(
        f"/cases/{case.id}/entity-resolution/{open_id}/approve", headers=headers
    ).json()
    assert approved["status"] == "APPROVED"
    assert approved["decision_actor"] == "HUMAN"
    assert len(live.graph_repo.fetch_inferred_links(case.id)) == 2

    # 8. Re-running changes nothing.
    again = client.post(f"/cases/{case.id}/entity-resolution/run", headers=headers).json()
    assert again["unchanged"] == again["candidates"]
    assert len(live.graph_repo.fetch_inferred_links(case.id)) == 2


def test_no_restricted_identifier_survives_the_whole_pipeline(live):
    """One sweep over every response an L2 reader can obtain."""
    client, case = live.client, live.case
    headers = live.authenticate()
    live.graph_service.ingest_case_evidence(case)
    client.post(f"/cases/{case.id}/entity-resolution/run", headers=headers)
    evidence_id = client.get(f"/cases/{case.id}/evidence", headers=headers).json()[
        "evidence"
    ][0]["evidence_id"]

    bodies = [
        client.get(f"/cases/{case.id}/evidence", headers=headers).text,
        client.get(f"/evidence/{evidence_id}?case_id={case.id}", headers=headers).text,
        client.get(f"/cases/{case.id}/graph", headers=headers).text,
        client.get(f"/cases/{case.id}/entity-resolution", headers=headers).text,
    ]

    for body in bodies:
        for value in RESTRICTED_VALUES:
            assert value not in body


def test_a_reader_without_the_case_reaches_nothing_in_the_pipeline(live):
    """The same walk, by someone who should see none of it."""
    client, case = live.client, live.case
    live.graph_service.ingest_case_evidence(case)
    live.grants.grant_case("USR-002", "FINANCIAL_CRIME", case.id, need_to_know=True)
    headers = live.authenticate("dev.analyst", agency_id="FINANCIAL_CRIME")

    responses = [
        client.get(f"/cases/{case.id}/evidence", headers=headers),
        client.get(f"/cases/{case.id}/graph", headers=headers),
        client.post(f"/cases/{case.id}/entity-resolution/run", headers=headers),
        client.get(f"/cases/{case.id}/entity-resolution", headers=headers),
    ]

    assert [response.status_code for response in responses] == [403, 403, 403, 403]
    for response in responses:
        for value in RESTRICTED_VALUES:
            assert value not in response.text
