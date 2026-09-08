"""GraphRepository contract for the Knowledge Graph plane (Neo4j).

Implementations own translation to/from the underlying graph database.
No caller outside this boundary should construct Cypher directly.
"""
from __future__ import annotations

from typing import Any, Protocol


class GraphRepository(Protocol):
    def upsert_node(self, label: str, key: str, properties: dict[str, Any]) -> None:
        """Create or update a node identified by (label, key)."""
        ...

    def upsert_relationship(
        self,
        from_key: str,
        rel_type: str,
        to_key: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Create or update a relationship between two existing nodes."""
        ...

    def query(self, cypher: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Run a read query and return rows as plain dicts."""
        ...
