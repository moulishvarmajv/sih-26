from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "SHADOW-INTEL"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
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
    
    # Blockchain / Cryptography Settings
    BLOCKCHAIN_NETWORK: str = "Ethereum / Hyperledger Besu (Local / Testnet)"
    ENABLE_MOCK_LEDGER: bool = True

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
