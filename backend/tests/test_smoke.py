"""Smoke tests: the application, configuration and composition root load cleanly."""
from app.api import dependencies
from app.core.config import settings
from app.main import app
from app.security.service import SecurityService


def test_settings_load():
    assert settings.PROJECT_NAME == "SHADOW-INTEL"
    assert settings.ENVIRONMENT == "development"


def test_app_imports():
    assert app.title == settings.PROJECT_NAME


def test_composition_root_wires_a_usable_security_service(tmp_path, monkeypatch):
    """Resets through `reset_providers`, which cannot miss a provider added later."""
    monkeypatch.setattr(settings, "EVENT_STORE_PATH", str(tmp_path / "events.db"))
    dependencies.reset_providers()

    service = dependencies.get_security_service()

    assert isinstance(service, SecurityService)
    assert dependencies.get_security_service() is service
    dependencies.get_event_store().close()
    dependencies.reset_providers()


def test_reset_providers_covers_every_cached_provider():
    """A provider left out of CACHED_PROVIDERS would leak state between tests."""
    cached = {
        name
        for name, value in vars(dependencies).items()
        if name.startswith("get_") and hasattr(value, "cache_clear")
    }

    assert cached == {provider.__name__ for provider in dependencies.CACHED_PROVIDERS}
