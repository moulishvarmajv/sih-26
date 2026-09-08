"""Composition root for API routes.

Routes depend on the SecurityService, never on the engine, policy document or
event store directly — and never evaluate authorization themselves.

Grants are in-memory for this phase, so they reset on restart; the persisted
implementation drops in behind AccessGrantRepository without touching routes.
"""
from __future__ import annotations

from functools import lru_cache

from app.core.config import settings
from app.infrastructure.sqlite_event_store import SQLiteEventStore
from app.security.authorization.policy_engine import ClearanceAuthorizationEngine
from app.security.grants import InMemoryAccessGrantRepository
from app.security.policy.loader import SecurityPolicy, load_security_policy
from app.security.service import SecurityService


@lru_cache(maxsize=1)
def get_security_policy() -> SecurityPolicy:
    return load_security_policy()


@lru_cache(maxsize=1)
def get_event_store() -> SQLiteEventStore:
    return SQLiteEventStore(settings.EVENT_STORE_PATH)


@lru_cache(maxsize=1)
def get_grant_repository() -> InMemoryAccessGrantRepository:
    return InMemoryAccessGrantRepository()


@lru_cache(maxsize=1)
def get_security_service() -> SecurityService:
    policy = get_security_policy()
    return SecurityService(
        engine=ClearanceAuthorizationEngine(policy),
        grants=get_grant_repository(),
        event_store=get_event_store(),
        clearance_policy=policy.clearance,
    )
