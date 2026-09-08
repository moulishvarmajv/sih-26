from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "SHADOW-INTEL"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"  # development | staging | production

    # Security & CORS
    SECRET_KEY: str = "sih-2026-shadow-intel-super-secret-key-mha"
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "*"
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

    # JWT placeholder configuration (authentication not yet implemented)
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

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
