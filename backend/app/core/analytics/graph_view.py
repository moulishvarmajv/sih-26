"""The only graph analytics is allowed to see.

This is the security boundary of the whole phase, and it is structural rather
than procedural. Analytics never touches a `GraphSnapshot`, a repository or a
driver. It receives an `AnalysableGraph` built from the already-authorized,
already-masked `AuthorizedGraph` that GraphService produces, and that type
carries no natural key at all — an entity is a hashed id, a label the privacy
policy already passed, and a type.

So a restricted identifier cannot leak through a signal by being forgotten in
one code path: there is no code path where analytics holds one. The scope
question — which evidence a reader may see — was already settled upstream, and
observations outside it never reach this module.

Adjacency is undirected for the structural analytics. Whether A called B or B
called A does not change whether A sits between two groups; direction is kept
separately, as in- and out-degree, where it is the thing being measured.

The view holds entities and the relationships between them. `Case` and
`Evidence` nodes, and the `OBSERVED_IN` / `BELONGS_TO` edges that reach them,
are provenance rather than structure: two phones are not connected because they
appeared in the same export. Including them would make the export the densest
node in every case and would join every group through it, which is exactly the
kind of artefact an investigator would then have to learn to ignore. Provenance
is not lost — every relationship still carries the evidence it came from.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

from app.core.analytics.models import AnalyticsEntity
from app.core.graph.models import (
    ENTITY_LABELS,
    ENTITY_RELATIONSHIPS,
    GraphNode,
    GraphRelationship,
)
from app.core.graph.service import AuthorizedGraph, node_display_label


@dataclass(frozen=True)
class ViewRelationship:
    """One authorized observation, reduced to what analytics needs."""

    relationship_id: str
    type: str
    source_id: str
    target_id: str
    evidence_id: str
    evidence_version_id: str
    observed_at: str
    #: When the source says the event happened, or None when it never said.
    #: Deliberately not defaulted to the ingestion time: an undated
    #: relationship would then cluster with every other undated one at the
    #: moment of ingestion and read as a burst of activity that never occurred.
    event_at: str | None
    duration_seconds: int
    #: Whether `duration_seconds` is a measurement. A call of zero seconds is a
    #: real, meaningful zero; a relationship that carries no duration at all is
    #: not a zero-second one.
    duration_measured: bool
    trust_class: str


@dataclass(frozen=True)
class AnalysableGraph:
    """An authorized case graph in a shape the metrics can work on."""

    case_id: str
    entities: Mapping[str, AnalyticsEntity]
    relationships: tuple[ViewRelationship, ...]
    evidence_ids: tuple[str, ...]
    masked_properties: tuple[str, ...]
    excluded_evidence_count: int
    truncated: bool = False
    adjacency: Mapping[str, frozenset[str]] = field(default_factory=dict)

    @property
    def entity_count(self) -> int:
        return len(self.entities)

    @property
    def relationship_count(self) -> int:
        return len(self.relationships)

    def entity(self, entity_id: str) -> AnalyticsEntity | None:
        return self.entities.get(entity_id)

    def neighbours(self, entity_id: str) -> frozenset[str]:
        return self.adjacency.get(entity_id, frozenset())

    def incident(self, entity_id: str) -> tuple[ViewRelationship, ...]:
        return tuple(
            relationship
            for relationship in self.relationships
            if entity_id in (relationship.source_id, relationship.target_id)
        )


def build_view(
    authorized: AuthorizedGraph,
    max_relationships: int,
    evidence_ids: Iterable[str] | None = None,
) -> AnalysableGraph:
    """Reduce an authorized graph to the analysable view.

    `max_relationships` bounds the work: a case with more observations than the
    policy allows is analysed over the first N in the repository's deterministic
    order and flagged `truncated`, rather than being refused or silently
    processed in full. Truncation is reported on every result that depends on it.
    """
    relationships: list[ViewRelationship] = []
    truncated = False
    for relationship in authorized.relationships:
        if relationship.type not in ENTITY_RELATIONSHIPS:
            # Provenance edges are how an entity is traced back to evidence, not
            # how it is connected to another entity. Counting them would make
            # every entity in one export a neighbour of every other, and the
            # densest node in every case would be the export itself.
            continue
        if len(relationships) >= max_relationships:
            truncated = True
            break
        reduced = _reduce(relationship)
        if reduced is not None:
            relationships.append(reduced)

    entities = {
        node.id: _entity(node)
        for node in authorized.nodes
        if node.label in ENTITY_LABELS
    }
    # A relationship whose endpoints are not in the node set cannot be analysed;
    # the repository returns both endpoints with every edge, so this only trims
    # a truncation boundary.
    relationships = [
        relationship
        for relationship in relationships
        if relationship.source_id in entities and relationship.target_id in entities
    ]

    adjacency: dict[str, set[str]] = {entity_id: set() for entity_id in entities}
    for relationship in relationships:
        if relationship.source_id == relationship.target_id:
            continue  # a self-loop adds no structure
        adjacency[relationship.source_id].add(relationship.target_id)
        adjacency[relationship.target_id].add(relationship.source_id)

    return AnalysableGraph(
        case_id=authorized.case_id,
        entities=entities,
        relationships=tuple(relationships),
        evidence_ids=tuple(sorted(evidence_ids if evidence_ids is not None else ())),
        masked_properties=authorized.masked_properties,
        excluded_evidence_count=authorized.excluded_evidence_count,
        truncated=truncated,
        adjacency={key: frozenset(value) for key, value in adjacency.items()},
    )


def _entity(node: GraphNode) -> AnalyticsEntity:
    """The disclosable projection of a node: hashed id, masked label, type."""
    return AnalyticsEntity(
        entity_id=node.id,
        entity_type=node.label.value,
        label=node_display_label(node),
    )


def _reduce(relationship: GraphRelationship) -> ViewRelationship | None:
    provenance = relationship.provenance
    if provenance is None:
        # Every observation carries provenance. One without it cannot be traced
        # back to evidence, so it is not something to build a signal on.
        return None
    properties = relationship.properties
    observed_at = provenance.observed_at
    return ViewRelationship(
        relationship_id=relationship.observation_id,
        type=relationship.type.value,
        source_id=relationship.start.id,
        target_id=relationship.end.id,
        evidence_id=provenance.evidence_id,
        evidence_version_id=provenance.evidence_version_id,
        observed_at=observed_at,
        event_at=_event_time(properties),
        duration_seconds=_int(properties.get("duration_seconds")),
        duration_measured="duration_seconds" in properties,
        trust_class=provenance.trust_class.value,
    )


def _event_time(properties: Mapping[str, object]) -> str | None:
    """The source's own time for this relationship, if it recorded one."""
    for key in ("timestamp", "first_observed_at"):
        value = properties.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
