"""Knowledge graph domain model.

Deliberately free of any Neo4j type: these are the objects that cross the
repository boundary in both directions, so nothing above the repository ever
sees a driver Node, Relationship or Record.

Provenance is attached to *observations* (the relationships derived from
evidence), not folded into the entity nodes. A Phone seen in three evidence
versions keeps three observation edges rather than one mutable "latest" record,
so lineage survives reprocessing.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from app.core.evidence.models import TrustClassification


class NodeLabel(str, Enum):
    PERSON = "Person"
    PHONE = "Phone"
    DEVICE = "Device"
    CASE = "Case"
    EVIDENCE = "Evidence"
    # Reserved for later phases; constrained in the schema, never written yet.
    ACCOUNT = "Account"
    CELL_TOWER = "CellTower"


class RelationshipType(str, Enum):
    USES = "USES"
    INSERTED_IN = "INSERTED_IN"
    CALLED = "CALLED"
    OBSERVED_IN = "OBSERVED_IN"
    BELONGS_TO = "BELONGS_TO"


#: The property that identifies a node of each label. Every MERGE keys on this,
#: and every constraint in the schema is built from this map.
NATURAL_KEY: Mapping[NodeLabel, str] = {
    NodeLabel.PERSON: "person_id",
    NodeLabel.PHONE: "msisdn",
    NodeLabel.DEVICE: "imei",
    NodeLabel.CASE: "case_id",
    NodeLabel.EVIDENCE: "evidence_id",
    NodeLabel.ACCOUNT: "number",
    NodeLabel.CELL_TOWER: "cgi",
}


def observation_id(*parts: str) -> str:
    """Deterministic identity for one observation.

    Derived from source-event data plus the evidence version, never random, so
    re-processing the same version merges onto the same edge while a genuinely
    new version records a new observation.
    """
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def node_ref_id(label: NodeLabel, key: str) -> str:
    """Opaque, stable id for API responses.

    Hashed so a masked node still has a usable identity: returning the raw key
    as the id would leak the very value the privacy policy redacted.
    """
    digest = hashlib.sha256(f"{label.value}|{key}".encode("utf-8")).hexdigest()
    return f"{label.value.lower()}:{digest[:16]}"


@dataclass(frozen=True)
class GraphProvenance:
    case_id: str
    evidence_id: str
    evidence_version_id: str
    source_type: str
    observed_at: str
    trust_class: TrustClassification
    processing_run_id: str | None = None

    def as_properties(self) -> dict[str, Any]:
        """Flatten to primitives; graph properties cannot hold nested maps."""
        properties = {
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "evidence_version_id": self.evidence_version_id,
            "source_type": self.source_type,
            "observed_at": self.observed_at,
            "trust_class": self.trust_class.value,
        }
        if self.processing_run_id is not None:
            properties["processing_run_id"] = self.processing_run_id
        return properties


@dataclass(frozen=True)
class NodeRef:
    label: NodeLabel
    key: str

    @property
    def id(self) -> str:
        return node_ref_id(self.label, self.key)


@dataclass(frozen=True)
class GraphNode:
    label: NodeLabel
    key: str
    properties: Mapping[str, Any] = field(default_factory=dict)

    @property
    def ref(self) -> NodeRef:
        return NodeRef(self.label, self.key)

    @property
    def id(self) -> str:
        return node_ref_id(self.label, self.key)


@dataclass(frozen=True)
class GraphRelationship:
    type: RelationshipType
    start: NodeRef
    end: NodeRef
    observation_id: str
    properties: Mapping[str, Any] = field(default_factory=dict)
    provenance: GraphProvenance | None = None

    def all_properties(self) -> dict[str, Any]:
        merged = dict(self.properties)
        if self.provenance is not None:
            merged.update(self.provenance.as_properties())
        merged["observation_id"] = self.observation_id
        return merged


@dataclass(frozen=True)
class GraphSnapshot:
    nodes: tuple[GraphNode, ...] = ()
    relationships: tuple[GraphRelationship, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.nodes or self.relationships)
