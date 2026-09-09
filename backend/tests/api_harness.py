"""Composes the real application stack for API tests.

The three API suites each need the same thing: real stores on a temporary path,
the synthetic identities seeded, every service wired the way the composition
root wires it, and the FastAPI dependencies overridden to point at them. That
setup was copied three times and drifted a little each time.

What stays in the test modules is the *scenario* — which cases exist, which
sources are ingested, who is granted what. Only the plumbing lives here, so a
suite still reads as a description of the behaviour it checks.

Every store is created under `tmp_path`, so a run leaves nothing behind and two
runs cannot see each other's data.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi.testclient import TestClient

from app.api import dependencies as deps
from app.core.analytics.policy import load_analytics_policy
from app.core.analytics.service import GraphAnalyticsService
from app.core.audit.event_store import EventStore
from app.core.debt.policy import load_debt_policy
from app.core.debt.service import EvidenceDebtService
from app.core.evidence.analysis import CdrSummaryAnalyzer
from app.core.evidence.service import EvidenceService
from app.core.graph.repository import GraphRepository
from app.core.graph.service import GraphService
from app.core.resolution.policy import load_resolution_policy
from app.core.resolution.service import EntityResolutionService
from app.infrastructure.local_object_store import LocalFileEvidenceObjectStore
from app.infrastructure.sqlite_analytics_repository import SQLiteAnalyticsRepository
from app.infrastructure.sqlite_case_repository import SQLiteCaseRepository
from app.infrastructure.sqlite_debt_repository import SQLiteEvidenceDebtRepository
from app.infrastructure.sqlite_evidence_repository import SQLiteEvidenceRepository
from app.infrastructure.sqlite_resolution_repository import SQLiteResolutionRepository
from app.main import app
from app.security.authentication import AuthenticationService
from app.security.authorization.policy_engine import ClearanceAuthorizationEngine
from app.security.grants import InMemoryAccessGrantRepository
from app.security.identity.local_provider import LocalIdentityProvider
from app.security.identity.passwords import ScryptPasswordHasher
from app.security.identity.seed import seed_development_identities
from app.security.identity.user_store import SQLiteUserStore
from app.security.policy.loader import SecurityPolicy
from app.security.service import SecurityService
from app.security.session.store import SQLiteSessionStore
from tests.graph_fakes import InMemoryGraphRepository

#: The seeded development accounts share this password. Test-only, and never a
#: default anywhere in the application — the seeder requires one explicitly.
PASSWORD = "dev-only-password"

#: Deliberately weak scrypt parameters. Real cost per login would add seconds
#: to every API test; the hashing itself is covered in the password tests.
_TEST_SCRYPT = {"n": 2**8, "r": 8, "p": 1}


@dataclass
class ApiHarness:
    """The wired application, plus the stores a test may need to inspect."""

    client: TestClient
    cases: SQLiteCaseRepository
    evidence_repo: SQLiteEvidenceRepository
    resolution_repo: SQLiteResolutionRepository
    analytics_repo: SQLiteAnalyticsRepository
    debt_repo: SQLiteEvidenceDebtRepository
    objects: LocalFileEvidenceObjectStore
    graph_repo: GraphRepository
    user_store: SQLiteUserStore
    session_store: SQLiteSessionStore
    hasher: ScryptPasswordHasher
    grants: InMemoryAccessGrantRepository
    event_store: EventStore
    security: SecurityService
    evidence_service: EvidenceService
    graph_service: GraphService
    resolution_service: EntityResolutionService
    analytics_service: GraphAnalyticsService
    debt_service: EvidenceDebtService

    def login(self, username: str = "dev.investigator") -> dict[str, str]:
        """Authenticate and return bearer headers, with no agency context selected."""
        response = self.client.post(
            "/auth/login", json={"username": username, "password": PASSWORD}
        )
        return {"Authorization": f"Bearer {response.json()['token']}"}

    def authenticate(
        self, username: str = "dev.investigator", agency_id: str = "POLICE"
    ) -> dict[str, str]:
        """Authenticate and select an agency context, returning ready-to-use headers."""
        headers = self.login(username)
        self.client.post(
            "/context/switch", json={"agency_id": agency_id}, headers=headers
        )
        return headers

    def close(self) -> None:
        app.dependency_overrides.clear()
        for store in (
            self.user_store,
            self.session_store,
            self.cases,
            self.evidence_repo,
            self.resolution_repo,
            self.analytics_repo,
            self.debt_repo,
        ):
            store.close()


def build_api_harness(
    tmp_path: Path,
    event_store: EventStore,
    grants: InMemoryAccessGrantRepository,
    policy: SecurityPolicy,
    graph_repository: GraphRepository | None = None,
) -> ApiHarness:
    """Wire the whole stack against temporary stores and override the app's dependencies.

    Every service is built, not only the ones a given suite exercises: the cost
    is negligible and it keeps the harness from encoding which suite needs what.
    """
    hasher = ScryptPasswordHasher(**_TEST_SCRYPT)
    user_store = SQLiteUserStore(tmp_path / "identity.db")
    session_store = SQLiteSessionStore(tmp_path / "identity.db")
    seed_development_identities(user_store, hasher, PASSWORD, grants)

    cases = SQLiteCaseRepository(tmp_path / "investigation.db")
    evidence_repo = SQLiteEvidenceRepository(tmp_path / "investigation.db")
    resolution_repo = SQLiteResolutionRepository(tmp_path / "investigation.db")
    analytics_repo = SQLiteAnalyticsRepository(tmp_path / "investigation.db")
    debt_repo = SQLiteEvidenceDebtRepository(tmp_path / "investigation.db")
    objects = LocalFileEvidenceObjectStore(tmp_path / "objects")
    graph_repo = graph_repository or InMemoryGraphRepository()

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
    resolution_service = EntityResolutionService(
        resolution_repository=resolution_repo,
        evidence_repository=evidence_repo,
        object_store=objects,
        graph_repository=graph_repo,
        security=security,
        event_store=event_store,
        policy=load_resolution_policy(),
        privacy=policy.privacy,
    )
    analytics_service = GraphAnalyticsService(
        graph_service=graph_service,
        graph_repository=graph_repo,
        analytics_repository=analytics_repo,
        event_store=event_store,
        policy=load_analytics_policy(),
    )
    debt_service = EvidenceDebtService(
        debt_repository=debt_repo,
        evidence_repository=evidence_repo,
        resolution_repository=resolution_repo,
        analytics_repository=analytics_repo,
        object_store=objects,
        security=security,
        event_store=event_store,
        policy=load_debt_policy(),
    )
    authentication = AuthenticationService(
        identity_provider=LocalIdentityProvider(user_store, hasher),
        session_store=session_store,
        event_store=event_store,
        clearance_policy=policy.clearance,
        session_ttl_minutes=60,
    )

    app.dependency_overrides.update(
        {
            deps.get_authentication_service: lambda: authentication,
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
            deps.get_resolution_repository: lambda: resolution_repo,
            deps.get_resolution_service: lambda: resolution_service,
            deps.get_analytics_repository: lambda: analytics_repo,
            deps.get_analytics_service: lambda: analytics_service,
            deps.get_debt_repository: lambda: debt_repo,
            deps.get_debt_service: lambda: debt_service,
        }
    )

    return ApiHarness(
        client=TestClient(app),
        cases=cases,
        evidence_repo=evidence_repo,
        resolution_repo=resolution_repo,
        analytics_repo=analytics_repo,
        debt_repo=debt_repo,
        objects=objects,
        graph_repo=graph_repo,
        user_store=user_store,
        session_store=session_store,
        hasher=hasher,
        grants=grants,
        event_store=event_store,
        security=security,
        evidence_service=evidence_service,
        graph_service=graph_service,
        resolution_service=resolution_service,
        analytics_service=analytics_service,
        debt_service=debt_service,
    )
