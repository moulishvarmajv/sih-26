"""Integration tests for inferred links against a real Neo4j.

Skipped unless a server is actually reachable, so the suite never depends on an
external service. To run them:

    docker compose up -d neo4j
    cd backend && python -m pytest tests/test_resolution_neo4j_integration.py

What only a real server can prove: that the Cypher for inferred links is valid,
that projecting the same decision twice merges onto one edge, that restating a
status touches inferred links and nothing else, and that an inference is invisible
to the observation read.

Every test writes under a case id unique to the run and removes only that
subgraph afterwards.
"""
import uuid

import pytest

from app.core.config import settings
from app.core.evidence.models import (
    EvidenceRecord,
    EvidenceState,
    EvidenceVersion,
    TrustClassification,
)
from app.core.graph.mapping import CdrGraphMapper
from app.core.graph.models import NodeLabel, RelationshipType
from app.core.resolution import projection
from app.core.resolution.models import (
    ConfidenceBand,
    DecidedBy,
    EntityObservationRef,
    EntityResolutionDecision,
    EntityType,
    MatchEvidence,
    MatchScore,
    MatchSignal,
    ReasonCode,
    Recommendation,
    ResolutionStatus,
    SignalOutcome,
    candidate_id_for,
    input_fingerprint,
    observation_key,
    resolution_id_for,
    resolution_lineage,
)
from app.infrastructure.neo4j_graph_repository import Neo4jGraphRepository

POLICY = "resolution-1.0.0"

CDR_PAYLOAD = {
    "export_id": "CDR-EXPORT-ER-IT",
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


def _repository() -> Neo4jGraphRepository:
    return Neo4jGraphRepository(
        uri=settings.NEO4J_URI,
        user=settings.NEO4J_USER,
        password=settings.NEO4J_PASSWORD,
        database=settings.NEO4J_DATABASE,
        connection_timeout=3.0,
    )


def _reachable() -> bool:
    try:
        repository = _repository()
        available = repository.is_available()
        repository.close()
        return available
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _reachable(), reason="no reachable Neo4j at NEO4J_URI; start it with docker compose"
)


@pytest.fixture
def case_id():
    return f"CASE-ER-IT-{uuid.uuid4().hex[:8].upper()}"


@pytest.fixture
def repository(case_id):
    repo = _repository()
    repo.initialize_schema()
    yield repo
    # Remove only this run's subgraph.
    repo._run("MATCH ()-[r]-() WHERE r.case_id = $case_id DELETE r", {"case_id": case_id})
    repo._run("MATCH (c:Case {case_id: $case_id}) DETACH DELETE c", {"case_id": case_id})
    repo._run("MATCH (n) WHERE NOT (n)--() AND n.msisdn IS NOT NULL DELETE n")
    repo._run("MATCH (n:Person) WHERE NOT (n)--() AND n.person_id STARTS WITH 'IT-' DELETE n")
    repo._run("MATCH (n:Person) WHERE NOT (n)--() AND n.person_id STARTS WITH 'SUB-IT-' DELETE n")
    repo._run("MATCH (n:Device) WHERE NOT (n)--() DELETE n")
    repo.close()


def make_decision(case_id, version=1, status=ResolutionStatus.AUTO_ACCEPTED, score_value=0.98):
    left = EntityObservationRef(
        observation_id=observation_key(EntityType.PERSON, "SUB-IT-0001", "EV-CDR-v1"),
        entity_type=EntityType.PERSON,
        entity_key="SUB-IT-0001",
        source_id="SYNTHETIC_CDR",
        evidence_id="EV-CDR",
        evidence_version_id="EV-CDR-v1",
        observed_at="2026-02-01T09:15:00+05:30",
    )
    right = EntityObservationRef(
        observation_id=observation_key(EntityType.PERSON, "IT-REG-0001", "EV-REG-v1"),
        entity_type=EntityType.PERSON,
        entity_key="IT-REG-0001",
        source_id="SYNTHETIC_SUBSCRIBER_REGISTER",
        evidence_id="EV-REG",
        evidence_version_id="EV-REG-v1",
        observed_at="2026-01-15T00:00:00+05:30",
    )
    lineage = resolution_lineage(case_id, EntityType.PERSON, left.entity_key, right.entity_key)
    return EntityResolutionDecision(
        resolution_id=resolution_id_for(lineage, version),
        lineage_id=lineage,
        resolution_version=version,
        case_id=case_id,
        entity_type=EntityType.PERSON,
        candidate_id=candidate_id_for(lineage, left.observation_id, right.observation_id),
        left=left,
        right=right,
        status=status,
        score=MatchScore(
            score=score_value,
            evidence_weight=0.7,
            confidence=ConfidenceBand.HIGH,
            confidence_floor=0.8,
            recommendation=Recommendation.MATCH,
            policy_version=POLICY,
            reasons=(ReasonCode.EXACT_PHONE_MATCH,),
            evidence=(
                MatchEvidence(
                    signal=MatchSignal.EXACT_PHONE,
                    attribute="phone",
                    outcome=SignalOutcome.AGREED,
                    weight=0.3,
                    contribution=0.3,
                ),
            ),
        ),
        policy_version=POLICY,
        input_fingerprint=input_fingerprint(left, right, POLICY),
        created_at="2026-02-02T00:00:00+00:00",
        decided_at="2026-02-02T00:00:00+00:00",
        decided_by=DecidedBy.SYSTEM.value,
        decision_actor=DecidedBy.SYSTEM,
    )


def project(repository, decision):
    nodes, links = projection.project([decision])
    repository.upsert_nodes(nodes)
    return repository.upsert_relationships(links)


def test_schema_creates_the_inferred_link_indexes(repository):
    """Idempotent DDL: initializing twice is a no-op, not an error."""
    repository.initialize_schema()

    indexes = repository._run("SHOW INDEXES YIELD name RETURN name")
    names = {row["name"] for row in indexes}
    assert "index_inferred_same_entity_resolution_id" in names
    assert "index_inferred_same_entity_case_id" in names


def test_an_accepted_decision_is_written_as_an_inferred_link(repository, case_id):
    decision = make_decision(case_id)

    project(repository, decision)

    links = repository.fetch_inferred_links(case_id)
    assert len(links) == 1
    assert links[0].type is RelationshipType.INFERRED_SAME_ENTITY
    assert links[0].properties["trust_class"] == TrustClassification.INFERRED.value
    assert links[0].properties["resolution_id"] == decision.resolution_id
    assert links[0].properties["policy_version"] == POLICY


def test_an_inferred_link_carries_both_source_evidence_versions(repository, case_id):
    project(repository, make_decision(case_id))

    link = repository.fetch_inferred_links(case_id)[0]

    assert sorted(link.properties["source_evidence_ids"]) == ["EV-CDR", "EV-REG"]
    assert sorted(link.properties["source_evidence_version_ids"]) == [
        "EV-CDR-v1",
        "EV-REG-v1",
    ]
    assert "EXACT_PHONE" in link.properties["supporting_signals"]


def test_projecting_the_same_decision_twice_merges_onto_one_edge(repository, case_id):
    decision = make_decision(case_id)

    project(repository, decision)
    project(repository, decision)

    assert len(repository.fetch_inferred_links(case_id)) == 1


def test_the_link_connects_the_two_person_nodes(repository, case_id):
    project(repository, make_decision(case_id))

    link = repository.fetch_inferred_links(case_id)[0]

    assert link.start.label is NodeLabel.PERSON
    assert link.end.label is NodeLabel.PERSON
    assert {link.start.key, link.end.key} == {"SUB-IT-0001", "IT-REG-0001"}


def test_a_status_restatement_touches_only_inferred_links(repository, case_id):
    """Observations stay write-once; only the inference's status can change."""
    record = EvidenceRecord(
        id="EV-CDR",
        case_id=case_id,
        source_id="SYNTHETIC_CDR",
        source_record_id="CDR-EXPORT-ER-IT",
        classification=TrustClassification.OBSERVED,
        state=EvidenceState.AVAILABLE,
        created_at="2026-02-01T00:00:00+00:00",
        security_level="L2",
    )
    version = EvidenceVersion(
        version_id="EV-CDR-v1",
        evidence_id="EV-CDR",
        version_number=1,
        content_hash="hash",
        payload_ref="ref",
        source_reference="dataset:CDR-EXPORT-ER-IT",
        ingested_at="2026-02-01T00:00:00+00:00",
    )
    snapshot = CdrGraphMapper().map(record, version, CDR_PAYLOAD)
    repository.upsert_nodes(snapshot.nodes)
    repository.upsert_relationships(snapshot.relationships)
    observed_before = repository.fetch_case_graph(case_id)
    decision = make_decision(case_id)
    project(repository, decision)

    updated = repository.update_inferred_link_status(
        decision.resolution_id, ResolutionStatus.REJECTED.value, "2026-02-03T00:00:00+00:00"
    )

    assert updated == 1
    link = repository.fetch_inferred_links(case_id)[0]
    assert link.properties["status"] == ResolutionStatus.REJECTED.value
    observed_after = repository.fetch_case_graph(case_id)
    assert {r.observation_id: dict(r.properties) for r in observed_after.relationships} == {
        r.observation_id: dict(r.properties) for r in observed_before.relationships
    }


def test_an_inference_is_not_returned_by_the_observation_read(repository, case_id):
    project(repository, make_decision(case_id))

    snapshot = repository.fetch_case_graph(case_id)

    assert all(
        relationship.type is not RelationshipType.INFERRED_SAME_ENTITY
        for relationship in snapshot.relationships
    )


def test_inferred_links_can_be_fetched_by_resolution(repository, case_id):
    decision = make_decision(case_id)
    project(repository, decision)

    assert repository.fetch_inferred_links(case_id, [decision.resolution_id])
    assert repository.fetch_inferred_links(case_id, ["ER-NOT-A-RESOLUTION-v1"]) == ()


def test_a_decision_that_asserts_nothing_is_never_projected(repository, case_id):
    pending = make_decision(case_id, status=ResolutionStatus.REVIEW_REQUIRED)

    nodes, links = projection.project([pending])

    assert (nodes, links) == ((), ())
    assert repository.fetch_inferred_links(case_id) == ()
