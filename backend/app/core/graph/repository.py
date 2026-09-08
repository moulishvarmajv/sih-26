"""GraphRepository contract for the Knowledge Graph plane.

Persistence and query only. Implementations own Cypher and the driver; callers
pass and receive the domain objects in `app.core.graph.models` and never see a
driver type. Authorization, case scoping decisions and audit belong to
GraphService, above this boundary.

Writes must be idempotent: applying the same nodes and relationships twice
leaves the graph unchanged.
"""
from __future__ import annotations

from typing import Protocol, Sequence

from app.core.graph.models import GraphNode, GraphRelationship, GraphSnapshot


class GraphRepositoryError(Exception):
    """Raised when the graph cannot be read or written."""


class GraphUnavailable(GraphRepositoryError):
    """Raised when the graph database cannot be reached at all."""


class GraphRepository(Protocol):
    def is_available(self) -> bool:
        """Return whether the graph backend is reachable. Never raises."""
        ...

    def initialize_schema(self) -> None:
        """Create constraints and indexes if absent.

        Safe to run repeatedly and non-destructive: it never drops or recreates
        anything, and never touches stored data.
        """
        ...

    def upsert_nodes(self, nodes: Sequence[GraphNode]) -> int:
        """Merge nodes on their natural key. Returns the number applied."""
        ...

    def upsert_relationships(self, relationships: Sequence[GraphRelationship]) -> int:
        """Merge relationships on their observation id. Returns the number applied."""
        ...

    def fetch_case_graph(
        self, case_id: str, evidence_ids: Sequence[str] | None = None
    ) -> GraphSnapshot:
        """Return the subgraph observed for one case.

        `evidence_ids`, when given, restricts the result to observations derived
        from those evidence items — the caller has already decided which ones
        this reader is allowed to see.
        """
        ...
