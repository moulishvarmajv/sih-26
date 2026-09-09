"""Projects accepted resolutions into the knowledge graph.

The rule this module exists to enforce: an inference is written *beside* the
observations, never over them. Nothing here touches an OBSERVED node property or
an observation edge. What it writes is one `INFERRED_SAME_ENTITY` relationship
carrying the resolution that produced it, the score and confidence, the policy
version and both source evidence versions — enough to explain, and to retract.

Node identity is merged, not created from nothing: the two Person nodes are the
ones the sources already named, and MERGE on the natural key is idempotent. The
edge's `observation_id` is derived from the resolution id, so re-projecting the
same decision merges onto the same edge rather than accumulating duplicates.

Only AUTO_ACCEPTED and APPROVED decisions are projected. A rejected or
superseded resolution has its link's status restated instead of deleted, so the
graph keeps the record that the system once inferred it.
"""
from __future__ import annotations

from typing import Sequence

from app.core.evidence.models import TrustClassification
from app.core.graph.models import (
    GraphNode,
    GraphRelationship,
    NodeLabel,
    RelationshipType,
    observation_id,
)
from app.core.resolution.models import EntityResolutionDecision, EntityType

#: Which graph label an entity type resolves to. Only PERSON is resolved in this
#: phase; the map is the seam where another entity type plugs in.
ENTITY_LABELS = {EntityType.PERSON: NodeLabel.PERSON}


class ProjectionError(Exception):
    """Raised when a decision cannot be projected into the graph."""


def label_for(entity_type: EntityType) -> NodeLabel:
    try:
        return ENTITY_LABELS[entity_type]
    except KeyError as exc:
        raise ProjectionError(f"no graph label for entity type '{entity_type.value}'") from exc


def inferred_link_observation_id(resolution_id: str) -> str:
    """Deterministic edge identity, so re-projecting a decision is idempotent."""
    return observation_id(RelationshipType.INFERRED_SAME_ENTITY.value, resolution_id)


def entity_nodes(decision: EntityResolutionDecision) -> tuple[GraphNode, ...]:
    """The two entity nodes the link connects.

    Merged on their natural key with no properties beyond it: this anchors an
    identity the sources already asserted, and adds no attribute the graph did
    not already have.
    """
    label = label_for(decision.entity_type)
    key_property = "person_id" if label is NodeLabel.PERSON else "key"
    return tuple(
        GraphNode(label=label, key=ref.entity_key, properties={key_property: ref.entity_key})
        for ref in _ordered_refs(decision)
    )


def inferred_link(decision: EntityResolutionDecision) -> GraphRelationship:
    """One INFERRED_SAME_ENTITY edge for an accepted decision.

    Direction is fixed by sorting the two entity keys, so the same pair always
    produces the same edge regardless of which observation was scored first.
    """
    if not decision.asserts_same_entity:
        raise ProjectionError(
            f"resolution '{decision.resolution_id}' is {decision.status.value} "
            "and asserts nothing to project"
        )
    label = label_for(decision.entity_type)
    left, right = _ordered_refs(decision)
    return GraphRelationship(
        type=RelationshipType.INFERRED_SAME_ENTITY,
        start=GraphNode(label=label, key=left.entity_key).ref,
        end=GraphNode(label=label, key=right.entity_key).ref,
        observation_id=inferred_link_observation_id(decision.resolution_id),
        properties={
            "case_id": decision.case_id,
            "resolution_id": decision.resolution_id,
            "lineage_id": decision.lineage_id,
            "resolution_version": decision.resolution_version,
            "status": decision.status.value,
            # The permanent trust axis. An inference is never relabelled
            # OBSERVED, whoever approved it.
            "trust_class": TrustClassification.INFERRED.value,
            "score": round(decision.score.score, 4),
            "confidence": decision.score.confidence.value,
            "evidence_weight": round(decision.score.evidence_weight, 4),
            "policy_version": decision.policy_version,
            "supporting_signals": [
                item.signal.value
                for item in decision.score.evidence
                if item.contribution > 0.0
            ],
            "conflicts": [conflict.rule for conflict in decision.score.conflicts],
            "source_evidence_ids": sorted(
                {decision.left.evidence_id, decision.right.evidence_id}
            ),
            "source_evidence_version_ids": sorted(
                {decision.left.evidence_version_id, decision.right.evidence_version_id}
            ),
            "decided_by": decision.decided_by or "",
            "decision_actor": (
                decision.decision_actor.value if decision.decision_actor else ""
            ),
            "created_at": decision.created_at,
        },
        # No GraphProvenance: that type describes *one* evidence version
        # observing something. An inference is derived from two, and both are
        # named on the edge instead of one being passed off as the source.
        provenance=None,
    )


def project(decisions: Sequence[EntityResolutionDecision]) -> tuple[
    tuple[GraphNode, ...], tuple[GraphRelationship, ...]
]:
    """Nodes and links for every decision that actually asserts an identity."""
    nodes: dict[tuple[NodeLabel, str], GraphNode] = {}
    links: dict[str, GraphRelationship] = {}
    for decision in decisions:
        if not decision.asserts_same_entity:
            continue
        for node in entity_nodes(decision):
            nodes.setdefault((node.label, node.key), node)
        link = inferred_link(decision)
        links.setdefault(link.observation_id, link)
    return tuple(nodes.values()), tuple(links.values())


def _ordered_refs(decision: EntityResolutionDecision):
    return tuple(
        sorted((decision.left, decision.right), key=lambda ref: ref.entity_key)
    )
