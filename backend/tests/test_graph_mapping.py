"""Evidence-to-graph mapping: deterministic, provenance-preserving, no inference."""
import pytest

from app.core.evidence.models import (
    EvidenceRecord,
    EvidenceState,
    EvidenceVersion,
    TrustClassification,
)
from app.core.graph.mapping import CdrGraphMapper, GraphMappingError, canonical_msisdn
from app.core.graph.models import NodeLabel, RelationshipType

PAYLOAD = {
    "export_id": "CDR-EXPORT-001",
    "records": [
        {
            "caller": "+919876543210",
            "callee": "+919812345678",
            "timestamp": "2026-02-01T09:15:00+05:30",
            "duration_seconds": 142,
            "imei": "356938035643809",
            "imsi": "404450123456789",
            "cell_id": "MH-PUNE-0442",
            "subscriber_id": "SUB-SYNTH-0001",
        },
        {
            # Same call, same digits, written differently and with no subscriber.
            "caller": "919876543210",
            "callee": "+91 98 1234 5678",
            "timestamp": "2026-02-01T11:02:13+05:30",
            "duration_seconds": 37,
            "imei": "356938035643809",
            "imsi": "404450987654321",
        },
    ],
}


def make_record(evidence_id="EV-1", case_id="CASE-001"):
    return EvidenceRecord(
        id=evidence_id,
        case_id=case_id,
        source_id="SYNTHETIC_CDR",
        source_record_id="CDR-EXPORT-001",
        classification=TrustClassification.OBSERVED,
        state=EvidenceState.AVAILABLE,
        created_at="2026-02-01T00:00:00+00:00",
        security_level="L2",
        sensitive_fields=("caller", "callee", "imei", "imsi"),
    )


def make_version(evidence_id="EV-1", number=1):
    return EvidenceVersion(
        version_id=f"{evidence_id}-v{number}",
        evidence_id=evidence_id,
        version_number=number,
        content_hash="a" * 64,
        payload_ref=f"CASE-001/{evidence_id}/v{number}/source.json",
        source_reference="SYNTHETIC-CDR-SAMPLE-1:CDR-EXPORT-001",
        ingested_at="2026-02-01T10:00:00+00:00",
    )


@pytest.fixture
def snapshot():
    return CdrGraphMapper().map(make_record(), make_version(), PAYLOAD)


def nodes_of(snapshot, label):
    return [node for node in snapshot.nodes if node.label is label]


def rels_of(snapshot, rel_type):
    return [rel for rel in snapshot.relationships if rel.type is rel_type]


def test_canonical_msisdn_normalises_formatting_only():
    assert canonical_msisdn("+919876543210") == "919876543210"
    assert canonical_msisdn("919876543210") == "919876543210"
    assert canonical_msisdn("+91 98 1234 5678") == "919812345678"
    with pytest.raises(GraphMappingError):
        canonical_msisdn("not-a-number")


def test_differently_formatted_numbers_key_the_same_phone_node(snapshot):
    phones = {node.key for node in nodes_of(snapshot, NodeLabel.PHONE)}

    assert phones == {"919876543210", "919812345678"}


def test_required_node_types_are_produced(snapshot):
    assert {node.label for node in snapshot.nodes} == {
        NodeLabel.CASE,
        NodeLabel.EVIDENCE,
        NodeLabel.PHONE,
        NodeLabel.DEVICE,
        NodeLabel.PERSON,
    }


def test_required_relationships_are_produced(snapshot):
    called = rels_of(snapshot, RelationshipType.CALLED)
    uses = rels_of(snapshot, RelationshipType.USES)
    inserted = rels_of(snapshot, RelationshipType.INSERTED_IN)

    assert len(called) == 2  # one per observed call
    assert called[0].start.label is NodeLabel.PHONE
    assert called[0].end.label is NodeLabel.PHONE
    assert len(uses) == 1  # only the row naming a subscriber
    assert uses[0].start.label is NodeLabel.PERSON
    assert inserted[0].start.label is NodeLabel.PHONE
    assert inserted[0].end.label is NodeLabel.DEVICE


def test_person_is_only_created_when_the_source_names_one():
    """Deriving a person from a phone number would be entity resolution."""
    payload = {"records": [dict(PAYLOAD["records"][1])]}  # no subscriber_id

    snapshot = CdrGraphMapper().map(make_record(), make_version(), payload)

    assert nodes_of(snapshot, NodeLabel.PERSON) == []
    assert rels_of(snapshot, RelationshipType.USES) == []


def test_every_observation_carries_provenance(snapshot):
    for relationship in snapshot.relationships:
        provenance = relationship.provenance
        assert provenance is not None
        assert provenance.case_id == "CASE-001"
        assert provenance.evidence_id == "EV-1"
        assert provenance.evidence_version_id == "EV-1-v1"
        assert provenance.source_type == "SYNTHETIC_CDR"
        assert provenance.observed_at == "2026-02-01T10:00:00+00:00"
        assert provenance.trust_class is TrustClassification.OBSERVED


def test_provenance_reaches_the_stored_properties(snapshot):
    call = rels_of(snapshot, RelationshipType.CALLED)[0]

    properties = call.all_properties()
    assert properties["evidence_version_id"] == "EV-1-v1"
    assert properties["trust_class"] == "OBSERVED"
    assert properties["observation_id"] == call.observation_id


def test_raw_values_are_preserved_next_to_canonical_keys(snapshot):
    raw_callers = {rel.properties["raw_caller"] for rel in rels_of(snapshot, RelationshipType.CALLED)}

    assert raw_callers == {"+919876543210", "919876543210"}


def test_mapping_is_deterministic():
    first = CdrGraphMapper().map(make_record(), make_version(), PAYLOAD)
    second = CdrGraphMapper().map(make_record(), make_version(), PAYLOAD)

    assert [n.key for n in first.nodes] == [n.key for n in second.nodes]
    assert [r.observation_id for r in first.relationships] == [
        r.observation_id for r in second.relationships
    ]


def test_a_new_version_records_new_observations_rather_than_rewriting(snapshot):
    """A new evidence version is a new observation, not a rewrite of the old one."""
    v2 = CdrGraphMapper().map(make_record(), make_version(number=2), PAYLOAD)

    def observation_ids(snap):
        return {
            rel.observation_id
            for rel in snap.relationships
            if rel.type is not RelationshipType.BELONGS_TO
        }

    assert observation_ids(snapshot).isdisjoint(observation_ids(v2))
    # The entities themselves are shared, so lineage accumulates on the edges.
    assert {n.key for n in snapshot.nodes} == {n.key for n in v2.nodes}


def test_structural_case_membership_is_version_independent(snapshot):
    """Evidence belongs to its case regardless of which version is current."""
    v2 = CdrGraphMapper().map(make_record(), make_version(number=2), PAYLOAD)

    assert (
        rels_of(snapshot, RelationshipType.BELONGS_TO)[0].observation_id
        == rels_of(v2, RelationshipType.BELONGS_TO)[0].observation_id
    )


def test_evidence_node_links_to_its_case(snapshot):
    belongs = rels_of(snapshot, RelationshipType.BELONGS_TO)

    assert len(belongs) == 1
    assert belongs[0].start.label is NodeLabel.EVIDENCE
    assert belongs[0].end.key == "CASE-001"


def test_entities_are_linked_to_the_evidence_that_observed_them(snapshot):
    observed = rels_of(snapshot, RelationshipType.OBSERVED_IN)

    assert {rel.start.label for rel in observed} == {
        NodeLabel.PHONE,
        NodeLabel.DEVICE,
        NodeLabel.PERSON,
    }
    assert all(rel.end.key == "EV-1" for rel in observed)


def test_malformed_payload_is_rejected():
    with pytest.raises(GraphMappingError):
        CdrGraphMapper().map(make_record(), make_version(), {"records": "not-a-list"})
    with pytest.raises(GraphMappingError):
        CdrGraphMapper().map(make_record(), make_version(), {"records": ["not-an-object"]})
