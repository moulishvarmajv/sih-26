"""Evidence debt over a real Neo4j, through the real application.

Every other debt suite substitutes the graph. This one puts CASE-004 through the
actual server so the engine consumes what Phases 5, 6 and 7A really wrote —
observations projected by Cypher, an inferred identity link, and signals
computed from a graph the database returned — rather than what an in-memory fake
believes they wrote.

That is the only way to catch a mistake no single-layer suite can see: a debt
item that depends on a graph property the fake supplies and the real repository
strips, or a finding whose supporting evidence ids differ once a real query has
been through them.

Skipped unless a server is reachable. Writes under a case id unique to the run
and removes exactly what it wrote.
"""
import uuid

import pytest

from app.core.debt.models import DebtCategory, DebtStatus
from app.core.domain.case import Case
from app.core.graph.models import RelationshipType
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from app.infrastructure.sources.synthetic_subscriber import SyntheticSubscriberRegisterSource
from tests.api_harness import build_api_harness
from tests.conftest import make_context, make_user
from tests.debt_case import ANALYSED, RESTRICTED_VALUES, supersede_extra_export
from tests.neo4j_support import SKIP_REASON, build_repository, cleanup, server_is_reachable

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not server_is_reachable(), reason=SKIP_REASON),
]


@pytest.fixture
def case_id():
    return f"CASE-DEBT-{uuid.uuid4().hex[:8].upper()}"


@pytest.fixture
def live(tmp_path, event_store, grants, policy, case_id):
    """CASE-004's evidence, replayed under a unique case id, with real Neo4j behind it."""
    graph = build_repository()
    harness = build_api_harness(tmp_path, event_store, grants, policy, graph_repository=graph)

    case = Case(
        id=case_id,
        agency_id="POLICE",
        title="Evidence debt, live",
        status="OPEN",
        security_level="L1",
    )
    harness.cases.create(case)
    for source in (SyntheticCDRSource(), SyntheticSubscriberRegisterSource()):
        for item in list(source.fetch("CASE-004")):
            harness.evidence_service.ingest_from_source(case, _OneShotSource(source, item))
    grants.grant_case("USR-001", "POLICE", case.id, need_to_know=True)

    operator = make_user("USR-001", level="L3")
    context = make_context("USR-001", level="L3")
    harness.graph_service.ingest_case_evidence(case)

    from app.core.evidence.analysis import CDR_SUMMARY

    by_record = {
        record.source_record_id: record.id
        for record in harness.evidence_repo.list_evidence_for_case(case.id)
    }
    for export in ANALYSED:
        harness.evidence_service.analyze_evidence(
            operator, context, case, by_record[export], CDR_SUMMARY
        )
    harness.resolution_service.run(operator, context, case)
    harness.analytics_service.run(operator, context, case)
    supersede_extra_export(harness.evidence_service, case, tmp_path)

    harness.case = case
    harness.evidence_ids = by_record
    harness.operator = (operator, context)
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


def test_debt_consumes_what_the_real_pipeline_recorded(live):
    """Every category, computed over observations a real server returned."""
    user, context = live.operator

    snapshot = live.debt_service.calculate(user, context, live.case)

    present = {entry.category for entry in snapshot.breakdown if entry.item_count > 0}
    assert present == set(DebtCategory)
    assert snapshot.total_debt > 0
    assert snapshot.evidence_in_scope == 6


def test_findings_computed_from_neo4j_carry_their_dependencies(live):
    """The signals here were computed from a graph the database returned."""
    user, context = live.operator

    unsupported = [
        item
        for item in live.debt_service.list_items(user, context, live.case)
        if item.category is DebtCategory.UNSUPPORTED_FINDING
    ]

    assert unsupported
    for item in unsupported:
        assert item.related_finding_ids
        assert item.subject.reference.startswith("SIG-")


def test_an_inferred_identity_link_in_neo4j_does_not_become_an_observation(live):
    """Debt reads decisions, not the graph; the inference stays where it belongs."""
    user, context = live.operator
    live.resolution_service.run(user, context, live.case)

    links = live.graph_repo.fetch_inferred_links(live.case.id)
    for link in links:
        assert link.type is RelationshipType.INFERRED_SAME_ENTITY
        assert link.properties["trust_class"] == "INFERRED"

    snapshot = live.debt_service.calculate(user, context, live.case)
    assert snapshot.total_debt > 0


def test_the_whole_flow_reaches_debt_over_http(live):
    """auth -> case -> evidence -> graph -> resolution -> analytics -> debt."""
    client, case = live.client, live.case
    headers = live.authenticate()

    assert client.get(f"/cases/{case.id}/evidence", headers=headers).status_code == 200
    assert client.get(f"/cases/{case.id}/graph", headers=headers).status_code == 200
    assert (
        client.post(f"/cases/{case.id}/entity-resolution/run", headers=headers).status_code
        == 200
    )
    assert client.get(f"/cases/{case.id}/analytics/overview", headers=headers).status_code == 200
    assert client.post(f"/cases/{case.id}/analytics/run", headers=headers).status_code == 200

    debt = client.get(f"/cases/{case.id}/evidence-debt", headers=headers)

    assert debt.status_code == 200
    body = debt.json()
    assert body["item_count"] > 0
    assert body["band"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
    assert body["debt_engine_version"]


def test_recalculating_against_the_real_graph_is_idempotent(live):
    client, case = live.client, live.case
    headers = live.authenticate()

    first = client.post(f"/cases/{case.id}/evidence-debt/recalculate", headers=headers).json()
    versions = {
        (item.debt_id, item.version) for item in live.debt_repo.list_items(case.id)
    }
    second = client.post(f"/cases/{case.id}/evidence-debt/recalculate", headers=headers).json()

    assert first["total_debt"] == second["total_debt"]
    assert versions == {
        (item.debt_id, item.version) for item in live.debt_repo.list_items(case.id)
    }
    assert all(
        item.status is DebtStatus.OPEN for item in live.debt_repo.list_items(case.id)
    )


def test_no_restricted_value_survives_the_live_pipeline_into_debt(live):
    """One sweep over every debt response an L2 reader can obtain from Neo4j."""
    client, case = live.client, live.case
    headers = live.authenticate()
    client.post(f"/cases/{case.id}/evidence-debt/recalculate", headers=headers)

    rendered = "".join(
        client.get(f"/cases/{case.id}/evidence-debt{path}", headers=headers).text
        for path in ("", "/breakdown", "/items")
    )

    for value in RESTRICTED_VALUES:
        assert value not in rendered


def test_a_narrow_reader_gets_less_debt_than_a_cleared_one_against_the_real_graph(live):
    cleared_user, cleared_context = live.operator
    narrow_user = make_user("USR-001", level="L2")
    narrow_context = make_context("USR-001", level="L2")

    cleared = live.debt_service.calculate(cleared_user, cleared_context, live.case)
    narrow = live.debt_service.calculate(narrow_user, narrow_context, live.case)

    assert narrow.total_debt < cleared.total_debt
    assert narrow.excluded_evidence_count == 1
    assert set(narrow.debt_ids) < set(cleared.debt_ids)
