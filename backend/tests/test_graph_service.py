"""GraphService: idempotent ingestion, case scoping, authorization and audit."""
import pytest

from app.core.audit.event_store import FlightRecorderEvent
from app.core.domain.case import Case
from app.core.evidence.analysis import CdrSummaryAnalyzer
from app.core.evidence.service import EvidenceService
from app.core.graph.models import NodeLabel, RelationshipType
from app.core.graph.repository import GraphUnavailable
from app.core.graph.service import GraphAccessDenied, GraphService
from app.infrastructure.local_object_store import LocalFileEvidenceObjectStore
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from app.infrastructure.sqlite_evidence_repository import SQLiteEvidenceRepository
from app.security.service import SecurityService
from tests.conftest import POLICE, make_context, make_user
from tests.graph_fakes import InMemoryGraphRepository

CASE = Case(id="CASE-001", agency_id="POLICE", title="Graph case", status="OPEN", security_level="L1")
OTHER_CASE = Case(
    id="CASE-002", agency_id="POLICE", title="Other case", status="OPEN", security_level="L1"
)


@pytest.fixture
def evidence_repo(tmp_path):
    repo = SQLiteEvidenceRepository(tmp_path / "investigation.db")
    yield repo
    repo.close()


@pytest.fixture
def objects(tmp_path):
    return LocalFileEvidenceObjectStore(tmp_path / "objects")


@pytest.fixture
def security(engine, grants, event_store, policy):
    return SecurityService(
        engine=engine, grants=grants, event_store=event_store, clearance_policy=policy.clearance
    )


@pytest.fixture
def graph_repo():
    return InMemoryGraphRepository()


@pytest.fixture
def evidence_service(evidence_repo, objects, security, event_store, policy):
    return EvidenceService(
        repository=evidence_repo,
        object_store=objects,
        security=security,
        event_store=event_store,
        privacy=policy.privacy,
        analyzers=(CdrSummaryAnalyzer(),),
    )


@pytest.fixture
def graph_service(graph_repo, evidence_repo, objects, security, event_store, policy):
    return GraphService(
        graph_repository=graph_repo,
        evidence_repository=evidence_repo,
        object_store=objects,
        security=security,
        event_store=event_store,
        privacy=policy.privacy,
    )


@pytest.fixture
def ingested(evidence_service, graph_service):
    evidence_service.ingest_from_source(CASE, SyntheticCDRSource())
    return graph_service.ingest_case_evidence(CASE)


def authorized_user(grants, level="L3", user_id="USR-104", case_ids=(CASE.id,)):
    user = make_user(user_id=user_id, level=level)
    grants.grant_agency(user.id, POLICE.id)
    for case_id in case_ids:
        grants.grant_case(user.id, POLICE.id, case_id, need_to_know=True)
    return user


# -- ingestion -------------------------------------------------------------


def test_ingestion_writes_nodes_and_relationships(graph_repo, ingested):
    assert ingested.evidence_processed == 2
    labels = {label for label, _ in graph_repo.nodes}
    assert {NodeLabel.PHONE, NodeLabel.DEVICE, NodeLabel.PERSON, NodeLabel.CASE} <= labels
    types = {rel.type for rel in graph_repo.relationships.values()}
    assert {RelationshipType.CALLED, RelationshipType.USES, RelationshipType.INSERTED_IN} <= types


def test_repeated_ingestion_is_idempotent(graph_service, graph_repo, ingested):
    nodes_before = dict(graph_repo.nodes)
    relationships_before = dict(graph_repo.relationships)

    graph_service.ingest_case_evidence(CASE)
    graph_service.ingest_case_evidence(CASE)

    assert graph_repo.nodes == nodes_before
    assert graph_repo.relationships == relationships_before


def test_schema_initialization_is_repeated_safely(graph_service, graph_repo, ingested):
    graph_service.ingest_case_evidence(CASE)

    assert graph_repo.schema_initialized >= 2  # ran again, and nothing broke


def test_a_new_evidence_version_adds_observations_without_replacing_old_ones(
    evidence_service, graph_service, graph_repo, ingested
):
    from app.core.evidence.models import TrustClassification
    from app.core.evidence.source import SourceEvidence

    class _Source:
        source_id = SyntheticCDRSource.source_id

        def fetch(self, case_id):
            return [
                SourceEvidence(
                    source_record_id="CDR-EXPORT-001",
                    payload={
                        "export_id": "CDR-EXPORT-001",
                        "records": [
                            {
                                "caller": "+919876543210",
                                "callee": "+919812345678",
                                "timestamp": "2026-03-01T09:15:00+05:30",
                                "duration_seconds": 10,
                                "imei": "356938035643809",
                                "imsi": "404450123456789",
                            }
                        ],
                    },
                    classification=TrustClassification.OBSERVED,
                    source_reference="TEST:CDR-EXPORT-001",
                    security_level="L2",
                    sensitive_fields=("caller", "callee", "imei", "imsi"),
                )
            ]

    v1_observations = {
        oid
        for oid, rel in graph_repo.relationships.items()
        if rel.type is RelationshipType.CALLED
    }
    evidence_service.ingest_from_source(CASE, _Source())
    graph_service.ingest_case_evidence(CASE)

    v2_observations = {
        oid
        for oid, rel in graph_repo.relationships.items()
        if rel.type is RelationshipType.CALLED
    }
    assert v1_observations < v2_observations  # old observations retained

    versions = {
        rel.provenance.evidence_version_id
        for rel in graph_repo.relationships.values()
        if rel.provenance is not None
    }
    assert len([v for v in versions if v.endswith("-v1")]) >= 1
    assert len([v for v in versions if v.endswith("-v2")]) >= 1


def test_ingestion_emits_start_and_completion_events(graph_service, event_store, ingested):
    started = event_store.list_by_type(FlightRecorderEvent.GRAPH_INGESTION_STARTED)
    completed = event_store.list_by_type(FlightRecorderEvent.GRAPH_INGESTION_COMPLETED)

    assert len(started) == 1
    assert completed[0].payload["evidence_processed"] == 2
    assert completed[0].case_id == CASE.id


def test_ingestion_failure_is_audited(evidence_service, graph_repo, graph_service, event_store):
    evidence_service.ingest_from_source(CASE, SyntheticCDRSource())
    graph_repo._available = False

    with pytest.raises(GraphUnavailable):
        graph_service.ingest_case_evidence(CASE)

    assert len(event_store.list_by_type(FlightRecorderEvent.GRAPH_INGESTION_FAILED)) == 1
    assert event_store.list_by_type(FlightRecorderEvent.GRAPH_INGESTION_COMPLETED) == []


# -- authorized read -------------------------------------------------------


def test_case_graph_returns_only_the_requested_case(
    evidence_service, graph_service, grants, ingested
):
    evidence_service.ingest_from_source(OTHER_CASE, SyntheticCDRSource())
    graph_service.ingest_case_evidence(OTHER_CASE)
    user = authorized_user(grants, case_ids=(CASE.id, OTHER_CASE.id))

    graph = graph_service.get_case_graph(user, make_context(level="L3"), CASE)

    assert graph.relationships
    assert {rel.provenance.case_id for rel in graph.relationships} == {CASE.id}


def test_unauthorized_case_is_denied(graph_service, grants, ingested):
    stranger = make_user(user_id="USR-777", level="L3")  # no agency or case grant

    with pytest.raises(GraphAccessDenied):
        graph_service.get_case_graph(
            stranger, make_context(user_id="USR-777", level="L3"), CASE
        )


def test_denied_graph_access_is_audited_and_returns_nothing(
    graph_service, grants, event_store, ingested
):
    stranger = make_user(user_id="USR-777", level="L3")

    with pytest.raises(GraphAccessDenied) as denial:
        graph_service.get_case_graph(
            stranger, make_context(user_id="USR-777", level="L3"), CASE
        )

    denied = event_store.list_by_type(FlightRecorderEvent.GRAPH_ACCESS_DENIED)
    assert len(denied) == 1
    assert denied[0].payload["reason"] == "AGENCY_ACCESS_DENIED"
    assert not hasattr(denial.value, "nodes")
    assert event_store.list_by_type(FlightRecorderEvent.GRAPH_ACCESS_ALLOWED) == []


def test_authorized_read_emits_query_and_allow_events(
    graph_service, grants, event_store, ingested
):
    user = authorized_user(grants)

    graph_service.get_case_graph(user, make_context(level="L3"), CASE)

    assert len(event_store.list_by_type(FlightRecorderEvent.GRAPH_QUERY_EXECUTED)) == 1
    allowed = event_store.list_by_type(FlightRecorderEvent.GRAPH_ACCESS_ALLOWED)
    assert len(allowed) == 1
    assert allowed[0].payload["node_count"] > 0
    assert allowed[0].actor_id == user.id


def test_full_clearance_sees_unmasked_identifiers(graph_service, grants, ingested):
    user = authorized_user(grants, level="L3")

    graph = graph_service.get_case_graph(user, make_context(level="L3"), CASE)

    phones = [n for n in graph.nodes if n.label is NodeLabel.PHONE]
    assert graph.masked_properties == ()
    assert any(node.properties["msisdn"] == "919876543210" for node in phones)


def test_partial_clearance_masks_graph_identifiers(graph_service, grants, ingested):
    """An L2 reader gets the same redaction in the graph as in the evidence view."""
    user = authorized_user(grants, level="L2", user_id="USR-500")

    graph = graph_service.get_case_graph(
        user, make_context(user_id="USR-500", level="L2"), CASE
    )

    assert "msisdn" in graph.masked_properties
    assert "imei" in graph.masked_properties
    phones = [n for n in graph.nodes if n.label is NodeLabel.PHONE]
    devices = [n for n in graph.nodes if n.label is NodeLabel.DEVICE]
    assert all(node.properties["msisdn"].startswith("XX-XXXX-") for node in phones)
    assert all(node.properties["imei"] == "***" for node in devices)
    assert "919876543210" not in str([dict(n.properties) for n in graph.nodes])


def test_masked_nodes_keep_distinct_identities(graph_service, grants, ingested):
    """Masking must not collapse different phones into one node."""
    user = authorized_user(grants, level="L2", user_id="USR-500")

    graph = graph_service.get_case_graph(
        user, make_context(user_id="USR-500", level="L2"), CASE
    )

    phones = [n for n in graph.nodes if n.label is NodeLabel.PHONE]
    assert len({node.id for node in phones}) == len(phones)


def test_evidence_the_reader_cannot_see_is_excluded_from_the_graph(
    evidence_service, graph_service, graph_repo, grants, ingested
):
    """Graph scope is built from authorized evidence, not filtered afterwards."""
    from app.core.evidence.models import TrustClassification
    from app.core.evidence.source import SourceEvidence

    class _SecretSource:
        source_id = "SECRET_CDR"

        def fetch(self, case_id):
            return [
                SourceEvidence(
                    source_record_id="SECRET-001",
                    payload={
                        "records": [
                            {
                                "caller": "+915550000001",
                                "callee": "+915550000002",
                                "timestamp": "2026-04-01T00:00:00+05:30",
                                "duration_seconds": 5,
                                "imei": "999999999999999",
                                "imsi": "404450000000000",
                            }
                        ]
                    },
                    classification=TrustClassification.OBSERVED,
                    source_reference="TEST:SECRET-001",
                    security_level="L3",  # above an L2 reader
                    sensitive_fields=("caller", "callee"),
                )
            ]

    evidence_service.ingest_from_source(CASE, _SecretSource())
    graph_service.ingest_case_evidence(CASE)
    user = authorized_user(grants, level="L2", user_id="USR-500")

    graph = graph_service.get_case_graph(
        user, make_context(user_id="USR-500", level="L2"), CASE
    )

    assert graph.excluded_evidence_count == 1
    assert "5550000001" not in str([dict(n.properties) for n in graph.nodes])
    assert all(
        rel.provenance.evidence_version_id.startswith("EV-") for rel in graph.relationships
    )


def test_graph_unavailable_propagates(graph_service, graph_repo, grants, ingested):
    user = authorized_user(grants)
    graph_repo._available = False

    with pytest.raises(GraphUnavailable):
        graph_service.get_case_graph(user, make_context(level="L3"), CASE)
