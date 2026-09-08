"""Core contracts import cleanly and are usable as typed classes.

This does not test behavior (there isn't any yet) — it proves the module
boundaries established in backend/app/{core,security,plugins,infrastructure}
are wired correctly and importable together without circular dependencies.
"""
from app.core.audit.event_store import EventStore
from app.core.evidence.source import EvidenceSource
from app.core.execution.executor import TaskExecutor
from app.core.graph.repository import GraphRepository
from app.infrastructure.integrity import IntegrityProvider
from app.plugins.base import AgencyPlugin
from app.security.authorization.engine import AuthorizationEngine
from app.security.identity.provider import IdentityProvider


def test_core_contracts_import_as_classes():
    for contract in (
        AgencyPlugin,
        EvidenceSource,
        GraphRepository,
        TaskExecutor,
        IdentityProvider,
        AuthorizationEngine,
        EventStore,
        IntegrityProvider,
    ):
        assert isinstance(contract, type)
