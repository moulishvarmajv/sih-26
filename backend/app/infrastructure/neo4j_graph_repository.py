"""Neo4j implementation of GraphRepository.

The driver is imported lazily so the rest of the application still imports,
starts and serves when the `neo4j` package or the server is absent — only
graph operations fail, and they fail with GraphUnavailable rather than an
import error.

Labels and relationship types cannot be parameterised in Cypher, so they are
interpolated into the query string. Every interpolated value comes from the
NodeLabel / RelationshipType enums, never from a request, and everything else
is passed as a parameter.
"""
from __future__ import annotations

import logging
from typing import Any, Sequence

from app.core.graph.models import (
    NATURAL_KEY,
    GraphNode,
    GraphPath,
    GraphProvenance,
    GraphRelationship,
    GraphSnapshot,
    NodeLabel,
    NodeRef,
    RelationshipType,
)
from app.core.graph.repository import GraphRepositoryError, GraphUnavailable
from app.core.evidence.models import TrustClassification

logger = logging.getLogger(__name__)

#: Uniqueness constraints, one per label that has a natural key. Creating a
#: constraint also creates the backing index, so lookups on these are indexed.
CONSTRAINED_LABELS: tuple[NodeLabel, ...] = (
    NodeLabel.PERSON,
    NodeLabel.PHONE,
    NodeLabel.DEVICE,
    NodeLabel.CASE,
    NodeLabel.EVIDENCE,
    NodeLabel.ACCOUNT,
    NodeLabel.CELL_TOWER,
)

#: Non-key lookups the case-graph query depends on.
RELATIONSHIP_INDEXES: tuple[tuple[RelationshipType, str], ...] = (
    (RelationshipType.CALLED, "case_id"),
    (RelationshipType.INSERTED_IN, "case_id"),
    (RelationshipType.USES, "case_id"),
    (RelationshipType.OBSERVED_IN, "case_id"),
    (RelationshipType.BELONGS_TO, "case_id"),
    (RelationshipType.INFERRED_SAME_ENTITY, "case_id"),
)

#: Inferred links are looked up by the resolution that produced them, so a
#: rejection or supersession can restate exactly those edges and no others.
INFERRED_LINK_INDEXES: tuple[tuple[RelationshipType, str], ...] = (
    (RelationshipType.INFERRED_SAME_ENTITY, "resolution_id"),
)

#: A hard ceiling on traversal depth, independent of any policy value. A
#: misconfigured policy should not be able to ask the database for an unbounded
#: walk.
_MAX_TRAVERSAL_DEPTH = 10

_PROVENANCE_KEYS = (
    "case_id",
    "evidence_id",
    "evidence_version_id",
    "source_type",
    "observed_at",
    "trust_class",
    "processing_run_id",
)


def constraint_statements() -> list[str]:
    """Idempotent schema DDL. `IF NOT EXISTS` makes re-running a no-op."""
    statements = []
    for label in CONSTRAINED_LABELS:
        key = NATURAL_KEY[label]
        name = f"constraint_{label.value.lower()}_{key}"
        statements.append(
            f"CREATE CONSTRAINT {name} IF NOT EXISTS "
            f"FOR (n:{label.value}) REQUIRE n.{key} IS UNIQUE"
        )
    for relationship, prop in RELATIONSHIP_INDEXES + INFERRED_LINK_INDEXES:
        name = f"index_{relationship.value.lower()}_{prop}"
        statements.append(
            f"CREATE INDEX {name} IF NOT EXISTS "
            f"FOR ()-[r:{relationship.value}]-() ON (r.{prop})"
        )
    # Observation identity is what makes ingestion idempotent, so it is indexed
    # for every observation-bearing relationship type.
    for relationship, _ in RELATIONSHIP_INDEXES:
        name = f"index_{relationship.value.lower()}_observation"
        statements.append(
            f"CREATE INDEX {name} IF NOT EXISTS "
            f"FOR ()-[r:{relationship.value}]-() ON (r.observation_id)"
        )
    return statements


class Neo4jGraphRepository:
    def __init__(
        self,
        uri: str,
        user: str,
        password: str,
        database: str = "neo4j",
        connection_timeout: float = 5.0,
    ) -> None:
        self._uri = uri
        self._auth = (user, password)
        self._database = database
        self._timeout = connection_timeout
        self._driver: Any | None = None

    # -- connection -------------------------------------------------------

    def _get_driver(self) -> Any:
        if self._driver is not None:
            return self._driver
        try:
            from neo4j import GraphDatabase
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise GraphUnavailable(
                "the 'neo4j' package is not installed; graph features are unavailable"
            ) from exc
        try:
            self._driver = GraphDatabase.driver(
                self._uri, auth=self._auth, connection_timeout=self._timeout
            )
        except Exception as exc:
            raise GraphUnavailable(f"cannot create Neo4j driver: {exc}") from exc
        return self._driver

    def is_available(self) -> bool:
        try:
            self._get_driver().verify_connectivity()
        except Exception as exc:
            logger.debug("Neo4j unavailable: %s", exc)
            return False
        return True

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None

    def _run(self, query: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        driver = self._get_driver()
        try:
            with driver.session(database=self._database) as session:
                result = session.run(query, parameters or {})
                return [record.data() for record in result]
        except GraphUnavailable:
            raise
        except Exception as exc:
            if _is_connectivity_error(exc):
                raise GraphUnavailable(f"Neo4j is unreachable: {exc}") from exc
            raise GraphRepositoryError(f"graph query failed: {exc}") from exc

    # -- schema -----------------------------------------------------------

    def initialize_schema(self) -> None:
        for statement in constraint_statements():
            self._run(statement)

    # -- writes -----------------------------------------------------------

    def upsert_nodes(self, nodes: Sequence[GraphNode]) -> int:
        applied = 0
        for label, batch in _group_by_label(nodes).items():
            key = NATURAL_KEY[label]
            self._run(
                f"UNWIND $rows AS row "
                f"MERGE (n:{label.value} {{{key}: row.key}}) "
                f"ON CREATE SET n += row.properties",
                {"rows": [{"key": node.key, "properties": dict(node.properties)} for node in batch]},
            )
            applied += len(batch)
        return applied

    def upsert_relationships(self, relationships: Sequence[GraphRelationship]) -> int:
        applied = 0
        for (rel_type, start_label, end_label), batch in _group_by_shape(relationships).items():
            start_key = NATURAL_KEY[start_label]
            end_key = NATURAL_KEY[end_label]
            self._run(
                f"UNWIND $rows AS row "
                f"MATCH (a:{start_label.value} {{{start_key}: row.start}}) "
                f"MATCH (b:{end_label.value} {{{end_key}: row.end}}) "
                f"MERGE (a)-[r:{rel_type.value} {{observation_id: row.observation_id}}]->(b) "
                # ON CREATE only: an observation, once recorded, is never rewritten.
                f"ON CREATE SET r += row.properties",
                {
                    "rows": [
                        {
                            "start": rel.start.key,
                            "end": rel.end.key,
                            "observation_id": rel.observation_id,
                            "properties": rel.all_properties(),
                        }
                        for rel in batch
                    ]
                },
            )
            applied += len(batch)
        return applied

    # -- reads ------------------------------------------------------------

    def fetch_case_graph(
        self, case_id: str, evidence_ids: Sequence[str] | None = None
    ) -> GraphSnapshot:
        """Return every observation scoped to a case, plus the nodes they touch.

        Scoping is on the relationship's own `case_id`, which is written from
        provenance at ingestion — the graph is never filtered client-side.
        """
        restrict = evidence_ids is not None
        rows = self._run(
            "MATCH (a)-[r]->(b) "
            "WHERE r.case_id = $case_id "
            # An inference is derived from two evidence items, so an
            # evidence-scoped read cannot authorize it. Excluded by type rather
            # than by scope, so the exclusion holds even for an unscoped read.
            "  AND type(r) <> $inferred "
            "  AND ($restrict = false OR r.evidence_id IN $evidence_ids) "
            "RETURN labels(a) AS start_labels, properties(a) AS start_props, "
            "       labels(b) AS end_labels, properties(b) AS end_props, "
            "       type(r) AS rel_type, properties(r) AS rel_props "
            "ORDER BY r.observation_id",
            {
                "case_id": case_id,
                "restrict": restrict,
                "evidence_ids": list(evidence_ids or ()),
                "inferred": RelationshipType.INFERRED_SAME_ENTITY.value,
            },
        )

        nodes: dict[tuple[NodeLabel, str], GraphNode] = {}
        relationships: list[GraphRelationship] = []
        for row in rows:
            start = _to_node(row["start_labels"], row["start_props"])
            end = _to_node(row["end_labels"], row["end_props"])
            if start is None or end is None:
                continue
            nodes.setdefault((start.label, start.key), start)
            nodes.setdefault((end.label, end.key), end)
            relationships.append(_to_relationship(row, start.ref, end.ref))
        return GraphSnapshot(tuple(nodes.values()), tuple(relationships))

    def find_shortest_path(
        self,
        case_id: str,
        start_key: str,
        end_key: str,
        evidence_ids: Sequence[str] | None = None,
        max_length: int = 6,
    ) -> GraphPath | None:
        """Bounded, case- and evidence-scoped shortest path.

        Two things are interpolated rather than parameterised, because Cypher
        does not accept parameters in either position: the traversal's upper
        bound, which is coerced to an int and clamped, and the excluded
        relationship type, which comes from an enum. Everything a caller
        supplies — keys, case id, evidence ids — is a parameter.

        The `ALL(...)` predicate is what keeps the search honest: every
        relationship on the returned path has to be inside the reader's scope,
        so the database routes around observations they may not see instead of
        returning a path that would have to be filtered out afterwards.
        """
        hops = max(1, min(int(max_length), _MAX_TRAVERSAL_DEPTH))
        restrict = evidence_ids is not None
        rows = self._run(
            "MATCH (a) WHERE a.msisdn = $start OR a.person_id = $start OR a.imei = $start "
            "MATCH (b) WHERE b.msisdn = $end OR b.person_id = $end OR b.imei = $end "
            "WITH a, b LIMIT 1 "
            f"MATCH p = shortestPath((a)-[*1..{hops}]-(b)) "
            "WHERE ALL(r IN relationships(p) WHERE "
            "  r.case_id = $case_id "
            f"  AND type(r) <> '{RelationshipType.INFERRED_SAME_ENTITY.value}' "
            "  AND ($restrict = false OR r.evidence_id IN $evidence_ids)) "
            "RETURN [n IN nodes(p) | {labels: labels(n), props: properties(n)}] AS path_nodes, "
            "       [r IN relationships(p) | {type: type(r), props: properties(r), "
            "         start_labels: labels(startNode(r)), start_props: properties(startNode(r)), "
            "         end_labels: labels(endNode(r)), end_props: properties(endNode(r))}] AS path_rels "
            "LIMIT 1",
            {
                "start": start_key,
                "end": end_key,
                "case_id": case_id,
                "restrict": restrict,
                "evidence_ids": list(evidence_ids or ()),
            },
        )
        if not rows:
            return None

        row = rows[0]
        nodes = []
        for entry in row["path_nodes"]:
            node = _to_node(entry["labels"], entry["props"])
            if node is None:
                return None  # a path through a node this model cannot name is not a path
            nodes.append(node)

        relationships = []
        for entry in row["path_rels"]:
            start = _to_node(entry["start_labels"], entry["start_props"])
            end = _to_node(entry["end_labels"], entry["end_props"])
            if start is None or end is None:
                return None
            relationships.append(
                _to_relationship(
                    {"rel_type": entry["type"], "rel_props": entry["props"]},
                    start.ref,
                    end.ref,
                )
            )
        return GraphPath(tuple(nodes), tuple(relationships))

    def fetch_inferred_links(
        self, case_id: str, resolution_ids: Sequence[str] | None = None
    ) -> tuple[GraphRelationship, ...]:
        restrict = resolution_ids is not None
        rows = self._run(
            f"MATCH (a)-[r:{RelationshipType.INFERRED_SAME_ENTITY.value}]->(b) "
            "WHERE r.case_id = $case_id "
            "  AND ($restrict = false OR r.resolution_id IN $resolution_ids) "
            "RETURN labels(a) AS start_labels, properties(a) AS start_props, "
            "       labels(b) AS end_labels, properties(b) AS end_props, "
            "       type(r) AS rel_type, properties(r) AS rel_props "
            "ORDER BY r.observation_id",
            {
                "case_id": case_id,
                "restrict": restrict,
                "resolution_ids": list(resolution_ids or ()),
            },
        )
        links: list[GraphRelationship] = []
        for row in rows:
            start = _to_node(row["start_labels"], row["start_props"])
            end = _to_node(row["end_labels"], row["end_props"])
            if start is None or end is None:
                continue
            links.append(_to_relationship(row, start.ref, end.ref))
        return tuple(links)

    def update_inferred_link_status(
        self, resolution_id: str, status: str, updated_at: str
    ) -> int:
        """Restate the status of one resolution's inferred links.

        Scoped to the relationship type in the MATCH itself, so this cannot
        reach an observation however it is called.
        """
        rows = self._run(
            f"MATCH ()-[r:{RelationshipType.INFERRED_SAME_ENTITY.value}]->() "
            "WHERE r.resolution_id = $resolution_id "
            "SET r.status = $status, r.status_updated_at = $updated_at "
            "RETURN count(r) AS updated",
            {"resolution_id": resolution_id, "status": status, "updated_at": updated_at},
        )
        return int(rows[0]["updated"]) if rows else 0


def _is_connectivity_error(exc: Exception) -> bool:
    name = type(exc).__name__
    return name in {
        "ServiceUnavailable",
        "SessionExpired",
        "AuthError",
        "ConfigurationError",
        "ConnectionAcquisitionTimeoutError",
    }


def _group_by_label(nodes: Sequence[GraphNode]) -> dict[NodeLabel, list[GraphNode]]:
    grouped: dict[NodeLabel, list[GraphNode]] = {}
    for node in nodes:
        grouped.setdefault(node.label, []).append(node)
    return grouped


def _group_by_shape(
    relationships: Sequence[GraphRelationship],
) -> dict[tuple[RelationshipType, NodeLabel, NodeLabel], list[GraphRelationship]]:
    grouped: dict[tuple[RelationshipType, NodeLabel, NodeLabel], list[GraphRelationship]] = {}
    for relationship in relationships:
        shape = (relationship.type, relationship.start.label, relationship.end.label)
        grouped.setdefault(shape, []).append(relationship)
    return grouped


def _to_node(labels: list[str], properties: dict[str, Any]) -> GraphNode | None:
    for raw in labels:
        try:
            label = NodeLabel(raw)
        except ValueError:
            continue
        key = properties.get(NATURAL_KEY[label])
        if key is None:
            continue
        return GraphNode(label=label, key=str(key), properties=dict(properties))
    return None


def _to_relationship(
    row: dict[str, Any], start: NodeRef, end: NodeRef
) -> GraphRelationship:
    """Rebuild one relationship, splitting provenance out only where it exists.

    An observation carries a single evidence version, so those properties are
    lifted into a GraphProvenance and removed from the property map. An inferred
    link has no single source version — it names both — so its `case_id` and
    `trust_class` are properties in their own right and stay where they are.
    Stripping them unconditionally would drop the very field that marks the edge
    INFERRED.
    """
    properties = dict(row["rel_props"])
    provenance = None
    if "evidence_id" in properties:
        try:
            trust = TrustClassification(properties.get("trust_class", ""))
        except ValueError:
            trust = TrustClassification.OBSERVED
        provenance = GraphProvenance(
            case_id=properties.get("case_id", ""),
            evidence_id=properties.get("evidence_id", ""),
            evidence_version_id=properties.get("evidence_version_id", ""),
            source_type=properties.get("source_type", ""),
            observed_at=properties.get("observed_at", ""),
            trust_class=trust,
            processing_run_id=properties.get("processing_run_id"),
        )
        properties = {k: v for k, v in properties.items() if k not in _PROVENANCE_KEYS}
    return GraphRelationship(
        type=RelationshipType(row["rel_type"]),
        start=start,
        end=end,
        observation_id=properties.get("observation_id", ""),
        properties=properties,
        provenance=provenance,
    )
