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
    monkeypatch.setattr(settings, "EVENT_STORE_PATH", str(tmp_path / "events.db"))
    for provider in (
        dependencies.get_security_policy,
        dependencies.get_event_store,
        dependencies.get_grant_repository,
        dependencies.get_security_service,
    ):
        provider.cache_clear()

    service = dependencies.get_security_service()

    assert isinstance(service, SecurityService)
    assert dependencies.get_security_service() is service
    dependencies.get_event_store().close()
    for provider in (
        dependencies.get_security_policy,
        dependencies.get_event_store,
        dependencies.get_grant_repository,
        dependencies.get_security_service,
    ):
        provider.cache_clear()
