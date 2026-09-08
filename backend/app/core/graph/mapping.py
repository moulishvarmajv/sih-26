"""Maps evidence into graph nodes and relationships.

Kept out of the repository on purpose: the repository knows Cypher, this knows
what a CDR row means. Mapping is deterministic — the same evidence version
always produces the same nodes, edges and observation ids.

Two rules this module is careful about:

- It never infers. A Person node appears only when the source actually reports a
  subscriber; deriving a person from a phone number would be entity resolution,
  which is not implemented, and would present an inference as an observation.
- It canonicalises *formatting* only. `+91 98 1234 5678` and `919812345678` are
  the same digits written differently, so both key the same Phone node, and the
  raw text as observed is preserved on the observation edge. Deciding that two
  *different* identifiers are the same entity remains out of scope.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from app.core.evidence.models import EvidenceRecord, EvidenceVersion, TrustClassification
from app.core.graph.models import (
    GraphNode,
    GraphProvenance,
    GraphRelationship,
    GraphSnapshot,
    NodeLabel,
    NodeRef,
    RelationshipType,
    observation_id,
)

_NON_DIGITS = re.compile(r"\D")


class GraphMappingError(Exception):
    """Raised when evidence cannot be mapped into the graph."""


def canonical_msisdn(raw: str) -> str:
    """Digits only.

    No country code is guessed: a number without one keys a different node than
    one with it, which is correct — assuming a country would be an inference.
    """
    digits = _NON_DIGITS.sub("", raw or "")
    if not digits:
        raise GraphMappingError(f"cannot canonicalise phone number {raw!r}")
    return digits


def canonical_identifier(raw: str, kind: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise GraphMappingError(f"missing {kind}")
    return value


class CdrGraphMapper:
    """Turns a CDR evidence version into graph elements."""

    source_type = "SYNTHETIC_CDR"

    def map(
        self,
        record: EvidenceRecord,
        version: EvidenceVersion,
        payload: Mapping[str, Any],
        processing_run_id: str | None = None,
    ) -> GraphSnapshot:
        rows = payload.get("records")
        if not isinstance(rows, list):
            raise GraphMappingError("CDR payload has no 'records' list")

        provenance = GraphProvenance(
            case_id=record.case_id,
            evidence_id=record.id,
            evidence_version_id=version.version_id,
            source_type=record.source_id or self.source_type,
            observed_at=version.ingested_at,
            # Structural facts read straight out of the source stay OBSERVED.
            trust_class=record.classification,
            processing_run_id=processing_run_id,
        )

        nodes: dict[tuple[NodeLabel, str], GraphNode] = {}
        relationships: dict[str, GraphRelationship] = {}

        case_node = GraphNode(
            label=NodeLabel.CASE,
            key=record.case_id,
            properties={"case_id": record.case_id},
        )
        evidence_node = GraphNode(
            label=NodeLabel.EVIDENCE,
            key=record.id,
            properties={
                "evidence_id": record.id,
                "case_id": record.case_id,
                "source_id": record.source_id,
                "source_record_id": record.source_record_id,
                "trust_class": record.classification.value,
                "security_level": record.security_level or "",
                "latest_version_id": version.version_id,
                "content_hash": version.content_hash,
            },
        )
        _add(nodes, case_node)
        _add(nodes, evidence_node)
        _link(
            relationships,
            GraphRelationship(
                type=RelationshipType.BELONGS_TO,
                start=evidence_node.ref,
                end=case_node.ref,
                observation_id=observation_id("BELONGS_TO", record.id, record.case_id),
                provenance=provenance,
            ),
        )

        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                raise GraphMappingError(f"CDR row {index} is not an object")
            self._map_row(row, index, nodes, relationships, provenance, evidence_node)

        return GraphSnapshot(
            nodes=tuple(nodes.values()), relationships=tuple(relationships.values())
        )

    def _map_row(
        self,
        row: Mapping[str, Any],
        index: int,
        nodes: dict[tuple[NodeLabel, str], GraphNode],
        relationships: dict[str, GraphRelationship],
        provenance: GraphProvenance,
        evidence_node: GraphNode,
    ) -> None:
        version_id = provenance.evidence_version_id
        caller_raw = str(row.get("caller", ""))
        callee_raw = str(row.get("callee", ""))
        caller = canonical_msisdn(caller_raw)
        callee = canonical_msisdn(callee_raw)
        imei = canonical_identifier(str(row.get("imei", "")), "imei")
        timestamp = canonical_identifier(str(row.get("timestamp", "")), "timestamp")

        caller_node = _add(nodes, GraphNode(NodeLabel.PHONE, caller, {"msisdn": caller}))
        callee_node = _add(nodes, GraphNode(NodeLabel.PHONE, callee, {"msisdn": callee}))
        device_node = _add(nodes, GraphNode(NodeLabel.DEVICE, imei, {"imei": imei}))

        # Phone -[:CALLED]-> Phone, one edge per observed call.
        _link(
            relationships,
            GraphRelationship(
                type=RelationshipType.CALLED,
                start=caller_node.ref,
                end=callee_node.ref,
                observation_id=observation_id(
                    "CALLED", caller, callee, timestamp, imei, version_id
                ),
                properties={
                    "timestamp": timestamp,
                    "duration_seconds": int(row.get("duration_seconds") or 0),
                    "cell_id": str(row.get("cell_id", "")),
                    # What the operator actually wrote, kept verbatim next to the
                    # canonical key so formatting is never silently rewritten.
                    "raw_caller": caller_raw,
                    "raw_callee": callee_raw,
                },
                provenance=provenance,
            ),
        )

        # Phone -[:INSERTED_IN]-> Device, i.e. this SIM was seen in this handset.
        imsi = str(row.get("imsi", "")).strip()
        _link(
            relationships,
            GraphRelationship(
                type=RelationshipType.INSERTED_IN,
                start=caller_node.ref,
                end=device_node.ref,
                observation_id=observation_id("INSERTED_IN", caller, imei, imsi, version_id),
                properties={"imsi": imsi, "first_observed_at": timestamp},
                provenance=provenance,
            ),
        )

        # Person -[:USES]-> Phone only when the source names a subscriber.
        subscriber_id = str(row.get("subscriber_id", "")).strip()
        if subscriber_id:
            person_node = _add(
                nodes,
                GraphNode(NodeLabel.PERSON, subscriber_id, {"person_id": subscriber_id}),
            )
            _link(
                relationships,
                GraphRelationship(
                    type=RelationshipType.USES,
                    start=person_node.ref,
                    end=caller_node.ref,
                    observation_id=observation_id("USES", subscriber_id, caller, version_id),
                    provenance=provenance,
                ),
            )
            _observed_in(relationships, person_node.ref, evidence_node.ref, provenance)

        for ref in (caller_node.ref, callee_node.ref, device_node.ref):
            _observed_in(relationships, ref, evidence_node.ref, provenance)


def _add(
    nodes: dict[tuple[NodeLabel, str], GraphNode], node: GraphNode
) -> GraphNode:
    """Deduplicate within one mapping pass; MERGE handles it across passes."""
    return nodes.setdefault((node.label, node.key), node)


def _link(relationships: dict[str, GraphRelationship], relationship: GraphRelationship) -> None:
    relationships.setdefault(relationship.observation_id, relationship)


def _observed_in(
    relationships: dict[str, GraphRelationship],
    entity: NodeRef,
    evidence: NodeRef,
    provenance: GraphProvenance,
) -> None:
    """Record which evidence version observed an entity, without mutating the entity."""
    _link(
        relationships,
        GraphRelationship(
            type=RelationshipType.OBSERVED_IN,
            start=entity,
            end=evidence,
            observation_id=observation_id(
                "OBSERVED_IN",
                entity.label.value,
                entity.key,
                provenance.evidence_version_id,
            ),
            provenance=provenance,
        ),
    )


def trust_class_of(snapshot: GraphSnapshot) -> Iterable[TrustClassification]:
    """Trust classes present in a snapshot, for assertions and reporting."""
    return {
        relationship.provenance.trust_class
        for relationship in snapshot.relationships
        if relationship.provenance is not None
    }
