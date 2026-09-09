"""Integration tests against a real Neo4j.

Skipped unless a server is actually reachable, so the suite never depends on an
external service. To run them:

    docker compose up -d neo4j
    cd backend && python -m pytest tests/test_neo4j_integration.py

Every test writes under a case id unique to the run and deletes only that
subgraph afterwards, so it cannot disturb other data in the database.
"""
import uuid

import pytest

from app.core.evidence.models import (
    EvidenceRecord,
    EvidenceState,
    EvidenceVersion,
    TrustClassification,
)
from app.core.graph.mapping import CdrGraphMapper
from app.core.graph.models import NodeLabel, RelationshipType
from app.infrastructure.neo4j_graph_repository import constraint_statements
from tests.neo4j_support import SKIP_REASON, build_repository, cleanup, server_is_reachable

PAYLOAD = {
    "export_id": "CDR-EXPORT-IT",
    "records": [
        {
            "caller": "+919876543210",
            "callee": "+919812345678",
            "timestamp": "2026-02-01T09:15:00+05:30",
            "duration_seconds": 142,
            "imei": "356938035643809",
            "imsi": "404450123456789",
            "subscriber_id": "SUB-IT-0001",
        }
    ],
}


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not server_is_reachable(), reason=SKIP_REASON),
]


@pytest.fixture
def case_id():
    """A case id unique to this test, so runs cannot see each other's data."""
    return f"CASE-IT-{uuid.uuid4().hex[:8].upper()}"


@pytest.fixture
def repository(case_id):
    repo = build_repository()
    repo.initialize_schema()
    yield repo
    cleanup(repo, case_id)
    repo.close()


def make_snapshot(case_id, version_number=1, payload=None):
    evidence_id = f"EV-IT-{case_id[-8:]}"
    record = EvidenceRecord(
        id=evidence_id,
        case_id=case_id,
        source_id="SYNTHETIC_CDR",
        source_record_id="CDR-EXPORT-IT",
        classification=TrustClassification.OBSERVED,
        state=EvidenceState.AVAILABLE,
        created_at="2026-02-01T00:00:00+00:00",
        security_level="L2",
        sensitive_fields=("caller", "callee", "imei", "imsi"),
    )
    version = EvidenceVersion(
        version_id=f"{evidence_id}-v{version_number}",
        evidence_id=evidence_id,
        version_number=version_number,
        content_hash=f"{version_number:064d}",
        payload_ref=f"{case_id}/{evidence_id}/v{version_number}/source.json",
        source_reference="INTEGRATION:CDR-EXPORT-IT",
        ingested_at=f"2026-02-0{version_number}T10:00:00+00:00",
    )
    return CdrGraphMapper().map(record, version, payload or PAYLOAD)


def apply(repository, snapshot):
    repository.upsert_nodes(snapshot.nodes)
    repository.upsert_relationships(snapshot.relationships)


def test_schema_initialization_is_idempotent(repository):
    repository.initialize_schema()
    repository.initialize_schema()

    existing = {row["name"] for row in repository._run("SHOW CONSTRAINTS YIELD name RETURN name")}
    for statement in constraint_statements():
        if statement.startswith("CREATE CONSTRAINT"):
            assert statement.split()[2] in existing


def test_entity_upsert_does_not_duplicate_nodes(repository, case_id):
    snapshot = make_snapshot(case_id)

    apply(repository, snapshot)
    apply(repository, snapshot)
    apply(repository, snapshot)

    rows = repository._run(
        "MATCH (p:Phone {msisdn: $msisdn}) RETURN count(p) AS count",
        {"msisdn": "919876543210"},
    )
    assert rows[0]["count"] == 1


def test_relationship_upsert_does_not_duplicate_relationships(repository, case_id):
    snapshot = make_snapshot(case_id)

    apply(repository, snapshot)
    apply(repository, snapshot)

    rows = repository._run(
        "MATCH ()-[r:CALLED]->() WHERE r.case_id = $case_id RETURN count(r) AS count",
        {"case_id": case_id},
    )
    assert rows[0]["count"] == 1


def test_provenance_round_trips(repository, case_id):
    apply(repository, make_snapshot(case_id))

    graph = repository.fetch_case_graph(case_id)

    called = [rel for rel in graph.relationships if rel.type is RelationshipType.CALLED]
    assert len(called) == 1
    provenance = called[0].provenance
    assert provenance is not None
    assert provenance.case_id == case_id
    assert provenance.evidence_version_id.endswith("-v1")
    assert provenance.trust_class is TrustClassification.OBSERVED
    assert provenance.source_type == "SYNTHETIC_CDR"


def test_evidence_version_lineage_is_preserved(repository, case_id):
    apply(repository, make_snapshot(case_id, version_number=1))
    apply(repository, make_snapshot(case_id, version_number=2))

    graph = repository.fetch_case_graph(case_id)

    called = [rel for rel in graph.relationships if rel.type is RelationshipType.CALLED]
    versions = {rel.provenance.evidence_version_id for rel in called}
    assert len(versions) == 2  # the v1 observation was not overwritten
    phones = [node for node in graph.nodes if node.label is NodeLabel.PHONE]
    assert len({node.key for node in phones}) == len(phones)  # entities still shared


def test_case_scoping_excludes_other_cases(repository, case_id):
    other_case = f"{case_id}-OTHER"
    apply(repository, make_snapshot(case_id))
    apply(repository, make_snapshot(other_case))
    try:
        graph = repository.fetch_case_graph(case_id)

        assert graph.relationships
        assert {rel.provenance.case_id for rel in graph.relationships} == {case_id}
    finally:
        repository._run(
            "MATCH ()-[r]-() WHERE r.case_id = $case_id DELETE r", {"case_id": other_case}
        )
        repository._run(
            "MATCH (c:Case {case_id: $case_id}) DETACH DELETE c", {"case_id": other_case}
        )


def test_evidence_scope_restricts_the_result(repository, case_id):
    apply(repository, make_snapshot(case_id))

    graph = repository.fetch_case_graph(case_id, evidence_ids=["EV-NOT-THIS-ONE"])

    assert graph.relationships == ()


def test_required_model_is_written(repository, case_id):
    apply(repository, make_snapshot(case_id))

    graph = repository.fetch_case_graph(case_id)

    assert {NodeLabel.PHONE, NodeLabel.DEVICE, NodeLabel.PERSON, NodeLabel.EVIDENCE} <= {
        node.label for node in graph.nodes
    }
    assert {
        RelationshipType.CALLED,
        RelationshipType.USES,
        RelationshipType.INSERTED_IN,
    } <= {rel.type for rel in graph.relationships}
