"""Shared plumbing for the live Neo4j suites.

Two things every integration test needs and neither should reinvent: a way to
decide whether a server is reachable, and a teardown that removes exactly what
the test wrote.

The teardown is the point. Deleting "every orphan node with an msisdn" would
reach outside the run — another suite's data, or a developer's own — so the
repository used here records the nodes it wrote and cleanup deletes those keys
and nothing else. Relationships are scoped by the run's unique case id.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Sequence

from app.core.config import settings
from app.core.graph.models import NATURAL_KEY, GraphNode, NodeLabel
from app.infrastructure.neo4j_graph_repository import Neo4jGraphRepository

CONNECTION_TIMEOUT = 3.0

SKIP_REASON = (
    "no reachable Neo4j at NEO4J_URI; start it with `docker compose up -d neo4j` "
    "(see docs/DEVELOPMENT.md)"
)


class TrackingNeo4jGraphRepository(Neo4jGraphRepository):
    """A real repository that remembers which nodes it wrote.

    Test-only. It changes nothing about how writes behave — it just makes
    precise cleanup possible, so a run cannot delete a node it did not create.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.written_nodes: set[tuple[NodeLabel, str]] = set()

    def upsert_nodes(self, nodes: Sequence[GraphNode]) -> int:
        self.written_nodes.update((node.label, node.key) for node in nodes)
        return super().upsert_nodes(nodes)


def build_repository() -> TrackingNeo4jGraphRepository:
    return TrackingNeo4jGraphRepository(
        uri=settings.NEO4J_URI,
        user=settings.NEO4J_USER,
        password=settings.NEO4J_PASSWORD,
        database=settings.NEO4J_DATABASE,
        connection_timeout=CONNECTION_TIMEOUT,
    )


@lru_cache(maxsize=1)
def server_is_reachable() -> bool:
    """Never raises: an unreachable server is a skip, not an error.

    Memoised because each integration module evaluates it at import time, and
    against a closed port the probe costs a connection timeout — about five
    seconds each, paid three times for an answer that cannot change within one
    pytest process.
    """
    try:
        repository = build_repository()
    except Exception:
        return False
    try:
        return repository.is_available()
    except Exception:
        return False
    finally:
        try:
            repository.close()
        except Exception:
            pass


def cleanup(repository: TrackingNeo4jGraphRepository, case_id: str) -> None:
    """Remove this run's subgraph, and only this run's.

    Relationships go by the case id the run generated, which nothing else uses.
    Nodes go by the exact keys this repository wrote, and only when they are
    left with no relationships — a node another case still references stays.
    """
    repository._run(
        "MATCH ()-[r]-() WHERE r.case_id = $case_id DELETE r", {"case_id": case_id}
    )
    repository._run(
        "MATCH (c:Case {case_id: $case_id}) DETACH DELETE c", {"case_id": case_id}
    )
    for label, key in sorted(repository.written_nodes, key=lambda item: (item[0].value, item[1])):
        repository._run(
            f"MATCH (n:{label.value} {{{NATURAL_KEY[label]}: $key}}) "
            "WHERE NOT (n)--() DELETE n",
            {"key": key},
        )
    repository.written_nodes.clear()
