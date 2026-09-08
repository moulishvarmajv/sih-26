import logging
import secrets

from pydantic import model_validator
from pydantic_settings import BaseSettings
from typing import List

logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    PROJECT_NAME: str = "SHADOW-INTEL"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
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

    # Graph & Storage Settings
    DATA_DIR: str = "data"

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

    # JWT placeholder configuration (sessions currently use opaque bearer tokens)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Clearance policy configuration
    CLEARANCE_POLICY_PATH: str = "app/security/policy/clearance_policy.json"

    # Logging
    LOG_LEVEL: str = "INFO"

    # Agency plugin configuration
    ENABLED_PLUGINS: List[str] = ["police", "cybercrime", "financial_crime"]

    # Blockchain / Cryptography Settings
    BLOCKCHAIN_NETWORK: str = "Ethereum / Hyperledger Besu (Local / Testnet)"
    ENABLE_MOCK_LEDGER: bool = True

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

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
