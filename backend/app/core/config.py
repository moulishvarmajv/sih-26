"""Application configuration.

Every setting here is read by something. A knob that looks configurable but is
never consulted is worse than no knob at all — it invites someone to change it
and conclude the system ignored them — so unused settings are removed rather
than kept "for later".

Unknown keys are rejected (`extra="forbid"`). A typo in `NEO4J_PASSWORD` should
stop startup, not silently fall back to a default; the same fail-closed
reasoning the authorization engine uses. The consequence is that `.env` may
contain only the fields defined below, which `tests/test_config_secrets.py`
holds `.env.example` to.
"""
import logging
import secrets

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        extra="forbid",
    )

    PROJECT_NAME: str = "SHADOW-INTEL"
    PROJECT_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"  # development | staging | production

    # Security & CORS.
    # SECRET_KEY must come from the environment. Outside production an ephemeral
    # one is generated per process, so no usable secret is ever committed and
    # local development still works with no setup.
    SECRET_KEY: str = ""
    # No "*" here: wildcard origins combined with credentialed requests would
    # expose session bearer tokens to any site.
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ]

    # Knowledge Graph (Neo4j) — local/open-source instance only, never managed cloud
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "shadowintel"
    NEO4J_DATABASE: str = "neo4j"

    # Flight Recorder event store — local SQLite, no managed DB
    EVENT_STORE_PATH: str = "data/event_store.db"

    # Local identity store: user accounts, roles and sessions
    IDENTITY_DB_PATH: str = "data/identity.db"
    SESSION_TTL_MINUTES: int = 60

    # Investigation state: cases, evidence metadata and entity-resolution
    # decisions (SQLite), with raw evidence payloads kept out of the database in
    # a local object store
    INVESTIGATION_DB_PATH: str = "data/investigation.db"
    EVIDENCE_OBJECT_ROOT: str = "data/evidence_objects"

    # Clearance and privacy policy
    CLEARANCE_POLICY_PATH: str = "app/security/policy/clearance_policy.json"

    # Entity resolution policy: matching weights, thresholds and conflict rules
    RESOLUTION_POLICY_PATH: str = "app/core/resolution/resolution_policy.json"

    # Logging
    LOG_LEVEL: str = "INFO"

    @model_validator(mode="after")
    def _require_secret_key(self) -> "Settings":
        if self.SECRET_KEY:
            return self
        if self.ENVIRONMENT == "production":
            raise ValueError("SECRET_KEY must be set in the environment for production")
        self.SECRET_KEY = secrets.token_urlsafe(32)
        logger.warning(
            "SECRET_KEY is unset; generated an ephemeral key for ENVIRONMENT=%s. "
            "Set SECRET_KEY in the environment for anything persistent.",
            self.ENVIRONMENT,
        )
        return self


settings = Settings()
