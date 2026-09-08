"""HTTP behaviour of the authorized graph endpoint."""
import json

import pytest
from fastapi.testclient import TestClient

from app.api import dependencies as deps
from app.core.audit.event_store import FlightRecorderEvent
from app.core.domain.case import Case
from app.core.evidence.analysis import CdrSummaryAnalyzer
from app.core.evidence.service import EvidenceService
from app.core.graph.service import GraphService
from app.infrastructure.local_object_store import LocalFileEvidenceObjectStore
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from app.infrastructure.sqlite_case_repository import SQLiteCaseRepository
from app.infrastructure.sqlite_evidence_repository import SQLiteEvidenceRepository
from app.main import app
from app.security.authentication import AuthenticationService
from app.security.authorization.policy_engine import ClearanceAuthorizationEngine
from app.security.identity.local_provider import LocalIdentityProvider
from app.security.identity.passwords import ScryptPasswordHasher
from app.security.identity.seed import seed_development_identities
from app.security.identity.user_store import SQLiteUserStore
from app.security.service import SecurityService
from app.security.session.store import SQLiteSessionStore
from tests.graph_fakes import InMemoryGraphRepository

PASSWORD = "dev-only-password"
CASE = Case(id="CASE-001", agency_id="POLICE", title="Graph case", status="OPEN", security_level="L1")


@pytest.fixture
def wired(tmp_path, event_store, grants, policy):
    hasher = ScryptPasswordHasher(n=2**8, r=8, p=1)
    user_store = SQLiteUserStore(tmp_path / "identity.db")
    session_store = SQLiteSessionStore(tmp_path / "identity.db")
    seed_development_identities(user_store, hasher, PASSWORD, grants)

    cases = SQLiteCaseRepository(tmp_path / "investigation.db")
    evidence_repo = SQLiteEvidenceRepository(tmp_path / "investigation.db")
    objects = LocalFileEvidenceObjectStore(tmp_path / "objects")
    graph_repo = InMemoryGraphRepository()
    cases.create(CASE)

    security = SecurityService(
        engine=ClearanceAuthorizationEngine(policy),
        grants=grants,
        event_store=event_store,
        clearance_policy=policy.clearance,
    )
    evidence_service = EvidenceService(
        repository=evidence_repo,
        object_store=objects,
        security=security,
        event_store=event_store,
        privacy=policy.privacy,
        analyzers=(CdrSummaryAnalyzer(),),
    )
    graph_service = GraphService(
        graph_repository=graph_repo,
        evidence_repository=evidence_repo,
        object_store=objects,
        security=security,
        event_store=event_store,
        privacy=policy.privacy,
    )
    evidence_service.ingest_from_source(CASE, SyntheticCDRSource())
    graph_service.ingest_case_evidence(CASE)
    grants.grant_case("USR-001", "POLICE", CASE.id, need_to_know=True)

    auth = AuthenticationService(
        identity_provider=LocalIdentityProvider(user_store, hasher),
        session_store=session_store,
        event_store=event_store,
        clearance_policy=policy.clearance,
        session_ttl_minutes=60,
    )
    app.dependency_overrides.update(
        {
            deps.get_authentication_service: lambda: auth,
            deps.get_security_service: lambda: security,
            deps.get_session_store: lambda: session_store,
            deps.get_user_store: lambda: user_store,
            deps.get_grant_repository: lambda: grants,
            deps.get_event_store: lambda: event_store,
            deps.get_security_policy: lambda: policy,
            deps.get_case_repository: lambda: cases,
            deps.get_evidence_repository: lambda: evidence_repo,
            deps.get_evidence_object_store: lambda: objects,
            deps.get_evidence_service: lambda: evidence_service,
            deps.get_graph_repository: lambda: graph_repo,
            deps.get_graph_service: lambda: graph_service,
        }
    )
    client = TestClient(app)
    client.graph_repo = graph_repo
    yield client
    app.dependency_overrides.clear()
    user_store.close()
    session_store.close()
    cases.close()
    evidence_repo.close()


def authenticate(client, username="dev.investigator"):
    token = client.post(
        "/auth/login", json={"username": username, "password": PASSWORD}
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/context/switch", json={"agency_id": "POLICE"}, headers=headers)
    return headers


def test_graph_requires_authentication(wired):
    response = wired.get(f"/cases/{CASE.id}/graph")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "SESSION_INVALID"}


def test_graph_requires_an_active_agency_context(wired):
    token = wired.post(
        "/auth/login", json={"username": "dev.investigator", "password": PASSWORD}
    ).json()["token"]

    response = wired.get(
        f"/cases/{CASE.id}/graph", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "NO_ACTIVE_CONTEXT"}


def test_authorized_graph_read_returns_nodes_and_relationships(wired):
    headers = authenticate(wired)

    response = wired.get(f"/cases/{CASE.id}/graph", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["case_id"] == CASE.id
    assert body["nodes"] and body["relationships"]
    labels = {node["label"] for node in body["nodes"]}
    assert {"Phone", "Device", "Person"} <= labels
    types = {rel["type"] for rel in body["relationships"]}
    assert {"CALLED", "USES", "INSERTED_IN"} <= types


def test_relationship_endpoints_reference_returned_node_ids(wired):
    headers = authenticate(wired)

    body = wired.get(f"/cases/{CASE.id}/graph", headers=headers).json()

    node_ids = {node["id"] for node in body["nodes"]}
    for relationship in body["relationships"]:
        assert relationship["source"] in node_ids
        assert relationship["target"] in node_ids


def test_response_carries_provenance(wired):
    headers = authenticate(wired)

    body = wired.get(f"/cases/{CASE.id}/graph", headers=headers).json()

    called = [rel for rel in body["relationships"] if rel["type"] == "CALLED"]
    provenance = called[0]["provenance"]
    assert provenance["evidence_id"].startswith("EV-")
    assert provenance["evidence_version_id"].endswith("-v1")
    assert provenance["trust_class"] == "OBSERVED"
    assert provenance["source_type"] == "SYNTHETIC_CDR"


def test_identifiers_are_masked_for_partial_clearance(wired):
    """USR-001 holds L2; the graph must redact exactly what the evidence view does."""
    headers = authenticate(wired)

    body = wired.get(f"/cases/{CASE.id}/graph", headers=headers).json()

    assert "msisdn" in body["masked_properties"]
    phones = [node for node in body["nodes"] if node["label"] == "Phone"]
    assert all(node["properties"]["msisdn"].startswith("XX-XXXX-") for node in phones)
    assert "919876543210" not in json.dumps(body)


def test_unknown_case_is_indistinguishable_from_denied(wired):
    headers = authenticate(wired)

    response = wired.get("/cases/CASE-404/graph", headers=headers)

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "CASE_ACCESS_DENIED"}


def test_unauthorized_reader_is_denied_without_graph_data(wired, event_store):
    """dev.analyst holds no POLICE grant, so it has no context to read with."""
    token = wired.post(
        "/auth/login", json={"username": "dev.analyst", "password": PASSWORD}
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    wired.post("/context/switch", json={"agency_id": "POLICE"}, headers=headers)

    response = wired.get(f"/cases/{CASE.id}/graph", headers=headers)

    assert response.status_code == 403
    assert "msisdn" not in response.text
    assert "CALLED" not in response.text


def test_graph_read_is_audited(wired, event_store):
    headers = authenticate(wired)

    wired.get(f"/cases/{CASE.id}/graph", headers=headers)

    allowed = event_store.list_by_type(FlightRecorderEvent.GRAPH_ACCESS_ALLOWED)
    queried = event_store.list_by_type(FlightRecorderEvent.GRAPH_QUERY_EXECUTED)
    assert len(allowed) == 1
    assert allowed[0].actor_id == "USR-001"
    assert allowed[0].case_id == CASE.id
    assert len(queried) == 1


def test_application_stays_healthy_when_the_graph_is_unavailable(wired):
    """Only graph-specific operations depend on Neo4j."""
    headers = authenticate(wired)
    wired.graph_repo._available = False

    assert wired.get("/health").status_code == 200
    assert wired.get("/ready").status_code == 200
    assert wired.get("/me", headers=headers).status_code == 200
    assert wired.get(f"/cases/{CASE.id}/evidence", headers=headers).status_code == 200

    graph = wired.get(f"/cases/{CASE.id}/graph", headers=headers)
    assert graph.status_code == 503
    assert graph.json()["detail"] == {"error": "GRAPH_UNAVAILABLE"}
