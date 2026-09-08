"""In-memory GraphRepository for tests.

Enforces the same identity rules as the Neo4j implementation — nodes keyed by
(label, natural key), relationships keyed by observation id — so idempotency and
scoping assertions here mean the same thing they mean against a real server.
The Cypher itself is covered by the integration test.
"""
from __future__ import annotations

from typing import Sequence

from app.core.graph.models import (
    GraphNode,
    GraphRelationship,
    GraphSnapshot,
    NodeLabel,
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
            if relationship.provenance is not None
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
