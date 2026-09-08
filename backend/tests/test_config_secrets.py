"""SECRET_KEY comes from the environment, never from source."""
import pytest
from pydantic import ValidationError

from app.core.config import Settings, settings


@pytest.fixture(autouse=True)
def no_ambient_secret(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)


def test_no_hardcoded_secret_remains():
    assert "sih-2026-shadow-intel-super-secret-key-mha" != settings.SECRET_KEY


def test_development_generates_an_ephemeral_secret_per_process():
    first = Settings(ENVIRONMENT="development", SECRET_KEY="")
    second = Settings(ENVIRONMENT="development", SECRET_KEY="")

    assert first.SECRET_KEY and second.SECRET_KEY
    assert first.SECRET_KEY != second.SECRET_KEY  # generated, not baked in


def test_production_without_a_configured_secret_is_rejected():
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        Settings(ENVIRONMENT="production", SECRET_KEY="")


def test_configured_secret_is_used_verbatim():
    configured = Settings(ENVIRONMENT="production", SECRET_KEY="from-the-environment")

    assert configured.SECRET_KEY == "from-the-environment"


def test_cors_defaults_do_not_allow_every_origin():
    """Wildcard origins with credentialed requests would expose session tokens."""
    assert "*" not in settings.ALLOWED_ORIGINS
