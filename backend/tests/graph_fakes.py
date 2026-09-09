"""In-memory GraphRepository for tests.

Enforces the same identity rules as the Neo4j implementation — nodes keyed by
(label, natural key), relationships keyed by observation id — so idempotency and
scoping assertions here mean the same thing they mean against a real server.
The Cypher itself is covered by the integration test.
"""
from __future__ import annotations

from typing import Sequence

from collections import deque

from app.core.graph.models import (
    GraphNode,
    GraphPath,
    GraphRelationship,
    GraphSnapshot,
    NodeLabel,
    RelationshipType,
)
from app.core.graph.repository import GraphUnavailable


class InMemoryGraphRepository:
    def __init__(self, available: bool = True) -> None:
        self._available = available
        self.nodes: dict[tuple[NodeLabel, str], GraphNode] = {}
        self.relationships: dict[str, GraphRelationship] = {}
        self.schema_initialized = 0

    def _check(self) -> None:
        if not self._available:
            raise GraphUnavailable("graph backend is offline")

    def is_available(self) -> bool:
        return self._available

    def initialize_schema(self) -> None:
        self._check()
        self.schema_initialized += 1

    def upsert_nodes(self, nodes: Sequence[GraphNode]) -> int:
        self._check()
        for node in nodes:
            self.nodes.setdefault((node.label, node.key), node)
        return len(nodes)

    def upsert_relationships(self, relationships: Sequence[GraphRelationship]) -> int:
        self._check()
        for relationship in relationships:
            # ON CREATE only: an existing observation is never overwritten.
            self.relationships.setdefault(relationship.observation_id, relationship)
        return len(relationships)

    def fetch_case_graph(
        self, case_id: str, evidence_ids: Sequence[str] | None = None
    ) -> GraphSnapshot:
        self._check()
        allowed = None if evidence_ids is None else set(evidence_ids)
        matched = [
            relationship
            for relationship in self.relationships.values()
            # Inferred links are excluded by type here for the same reason the
            # Cypher excludes them: they are derived from two evidence items,
            # so an evidence-scoped read cannot authorize them.
            if relationship.type is not RelationshipType.INFERRED_SAME_ENTITY
            and relationship.provenance is not None
            and relationship.provenance.case_id == case_id
            and (allowed is None or relationship.provenance.evidence_id in allowed)
        ]
        keys = {ref for rel in matched for ref in (rel.start, rel.end)}
        nodes = tuple(
            self.nodes[(ref.label, ref.key)]
            for ref in keys
            if (ref.label, ref.key) in self.nodes
        )
        return GraphSnapshot(nodes=nodes, relationships=tuple(matched))

    def fetch_inferred_links(
        self, case_id: str, resolution_ids: Sequence[str] | None = None
    ) -> tuple[GraphRelationship, ...]:
        self._check()
        allowed = None if resolution_ids is None else set(resolution_ids)
        return tuple(
            relationship
            for relationship in self.relationships.values()
            if relationship.type is RelationshipType.INFERRED_SAME_ENTITY
            and relationship.properties.get("case_id") == case_id
            and (allowed is None or relationship.properties.get("resolution_id") in allowed)
        )

    def update_inferred_link_status(
        self, resolution_id: str, status: str, updated_at: str
    ) -> int:
        """Restates status on inferred links only; observations stay write-once."""
        self._check()
        updated = 0
        for observation_id, relationship in list(self.relationships.items()):
            if relationship.type is not RelationshipType.INFERRED_SAME_ENTITY:
                continue
            if relationship.properties.get("resolution_id") != resolution_id:
                continue
            properties = dict(relationship.properties)
            properties["status"] = status
            properties["status_updated_at"] = updated_at
            self.relationships[observation_id] = GraphRelationship(
                type=relationship.type,
                start=relationship.start,
                end=relationship.end,
                observation_id=relationship.observation_id,
                properties=properties,
                provenance=relationship.provenance,
            )
            updated += 1
        return updated

    def find_shortest_path(
        self,
        case_id: str,
        start_key: str,
        end_key: str,
        evidence_ids: Sequence[str] | None = None,
        max_length: int = 6,
    ) -> GraphPath | None:
        """Breadth-first over the same scope the Cypher applies.

        The real repository lets the database walk the graph; this walks it in
        Python. What both must agree on is the *scope* — case, evidence and the
        exclusion of inferred links — so a test that passes here means the same
        thing it means against Neo4j. The Cypher itself is covered by the
        integration suite.
        """
        self._check()
        allowed = None if evidence_ids is None else set(evidence_ids)
        usable = [
            relationship
            for relationship in self.relationships.values()
            if relationship.type is not RelationshipType.INFERRED_SAME_ENTITY
            and relationship.provenance is not None
            and relationship.provenance.case_id == case_id
            and (allowed is None or relationship.provenance.evidence_id in allowed)
        ]
        nodes_by_key = {
            (node.label, node.key): node for node in self.nodes.values()
        }

        def resolve(key: str):
            return [ref for ref in nodes_by_key if ref[1] == key]

        starts, ends = resolve(start_key), resolve(end_key)
        if not starts or not ends:
            return None
        start, end = starts[0], ends[0]
        if start == end:
            return None

        adjacency: dict[tuple, list[tuple]] = {}
        for relationship in usable:
            left = (relationship.start.label, relationship.start.key)
            right = (relationship.end.label, relationship.end.key)
            adjacency.setdefault(left, []).append((right, relationship))
            adjacency.setdefault(right, []).append((left, relationship))

        queue = deque([(start, [])])
        seen = {start}
        while queue:
            node, walk = queue.popleft()
            if len(walk) >= max_length:
                continue
            for neighbour, relationship in sorted(
                adjacency.get(node, []), key=lambda item: item[1].observation_id
            ):
                if neighbour in seen:
                    continue
                path = walk + [relationship]
                if neighbour == end:
                    ordered = _ordered_nodes(start, path)
                    return GraphPath(
                        tuple(nodes_by_key[ref] for ref in ordered if ref in nodes_by_key),
                        tuple(path),
                    )
                seen.add(neighbour)
                queue.append((neighbour, path))
        return None


def _ordered_nodes(start, relationships):
    """Walk the relationship chain, recording the node reached at each hop."""
    ordered = [start]
    current = start
    for relationship in relationships:
        left = (relationship.start.label, relationship.start.key)
        right = (relationship.end.label, relationship.end.key)
        current = right if current == left else left
        ordered.append(current)
    return ordered
