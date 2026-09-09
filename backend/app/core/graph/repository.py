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

from app.core.graph.models import GraphNode, GraphPath, GraphRelationship, GraphSnapshot


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

        Inferred links are not returned here: they are derived from *two*
        evidence items, so a scope built for single-evidence observations cannot
        authorize them. They are served by the entity resolution API, which
        authorizes both sides.
        """
        ...

    def find_shortest_path(
        self,
        case_id: str,
        start_key: str,
        end_key: str,
        evidence_ids: Sequence[str] | None = None,
        max_length: int = 6,
    ) -> GraphPath | None:
        """Return the shortest observed walk between two entities, or None.

        Implemented here rather than above the boundary because the database can
        answer it without the caller loading the graph: a bounded `shortestPath`
        is one query, where fetching a case subgraph to walk it in Python would
        scale with the case rather than with the answer.

        `max_length` bounds the traversal, and `evidence_ids` scopes it to what
        the caller has already decided this reader may see — an observation
        outside that scope is not a usable step, so the path has to route around
        it or not exist.
        """
        ...

    def fetch_inferred_links(
        self, case_id: str, resolution_ids: Sequence[str] | None = None
    ) -> tuple[GraphRelationship, ...]:
        """Return the INFERRED_SAME_ENTITY links written for one case.

        Separate from `fetch_case_graph` on purpose: an inference is not an
        observation, and reading one requires authorizing every evidence item it
        was derived from.
        """
        ...

    def update_inferred_link_status(
        self, resolution_id: str, status: str, updated_at: str
    ) -> int:
        """Restate the status of the inferred links for one resolution.

        The single mutation this interface permits, and it is confined to
        INFERRED_SAME_ENTITY: an inference can be rejected or superseded, so its
        status is not a fact frozen at write time. Observations remain
        write-once — no method here can alter one.
        """
        ...
