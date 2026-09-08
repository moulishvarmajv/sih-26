"""Neo4j repository boundary, without needing a server.

Covers the schema DDL and the unreachable-backend behaviour. Round-tripping
actual data is covered by tests/test_neo4j_integration.py against a real server.
"""
import pytest

from app.core.graph.models import NATURAL_KEY, NodeLabel
from app.core.graph.repository import GraphUnavailable
from app.infrastructure.neo4j_graph_repository import (
    CONSTRAINED_LABELS,
    Neo4jGraphRepository,
    constraint_statements,
)

#: A port nothing listens on, so connection attempts fail immediately.
UNREACHABLE = "bolt://127.0.0.1:1"


@pytest.fixture
def offline():
    repository = Neo4jGraphRepository(
        UNREACHABLE, "neo4j", "not-a-real-password", connection_timeout=0.5
    )
    yield repository
    repository.close()


def test_schema_constrains_every_required_identifier():
    statements = " ".join(constraint_statements())

    for label, key in [
        (NodeLabel.PERSON, "person_id"),
        (NodeLabel.PHONE, "msisdn"),
        (NodeLabel.DEVICE, "imei"),
        (NodeLabel.ACCOUNT, "number"),
        (NodeLabel.CELL_TOWER, "cgi"),
        (NodeLabel.CASE, "case_id"),
        (NodeLabel.EVIDENCE, "evidence_id"),
    ]:
        assert NATURAL_KEY[label] == key
        assert f"FOR (n:{label.value}) REQUIRE n.{key} IS UNIQUE" in statements


def test_schema_is_idempotent_and_non_destructive():
    statements = constraint_statements()

    assert statements, "schema must define something"
    for statement in statements:
        assert "IF NOT EXISTS" in statement
        upper = statement.upper()
        for forbidden in ("DROP", "DELETE", "REMOVE", "DETACH"):
            assert forbidden not in upper


def test_schema_statements_are_unique():
    statements = constraint_statements()

    assert len(statements) == len(set(statements))
    assert len([s for s in statements if s.startswith("CREATE CONSTRAINT")]) == len(
        CONSTRAINED_LABELS
    )


def test_is_available_reports_false_instead_of_raising(offline):
    assert offline.is_available() is False


def test_operations_fail_closed_when_unreachable(offline):
    with pytest.raises(GraphUnavailable):
        offline.initialize_schema()
    with pytest.raises(GraphUnavailable):
        offline.fetch_case_graph("CASE-001")
