"""Configuration behaviour: secrets, CORS, and the documented example file.

The `.env.example` tests exist because that file had drifted from the code in
two ways at once — a policy path that no longer resolved, and a key that is not
a setting at all — so following its own instructions broke startup. Loading it
here is what stops that recurring.
"""
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.security.policy.loader import load_security_policy

ENV_EXAMPLE = Path(__file__).resolve().parents[1] / ".env.example"


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


# -- the documented example environment file --------------------------------


def env_example_settings() -> Settings:
    return Settings(_env_file=ENV_EXAMPLE)


def test_the_example_env_file_exists_where_the_docs_say_it_does():
    assert ENV_EXAMPLE.is_file()


def test_the_example_env_file_loads_as_valid_settings():
    """Copying `.env.example` to `.env` must not break startup.

    Unknown keys are rejected, so a key documented here that is not a setting
    would stop the application from starting at all.
    """
    assert env_example_settings().ENVIRONMENT == "development"


def test_every_key_in_the_example_file_is_a_real_setting():
    documented = {
        line.split("=", 1)[0].strip()
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.strip().startswith("#")
    }

    assert documented <= set(Settings.model_fields)
    assert documented, "the example file should document the settings that exist"


def test_the_example_policy_paths_resolve_to_real_documents():
    """A wrong policy path in the example file fails closed at startup."""
    configured = env_example_settings()

    policy = load_security_policy(configured.CLEARANCE_POLICY_PATH)

    assert policy.clearance.levels
    assert policy.privacy.maskable_fields


def test_the_example_resolution_policy_path_resolves():
    from app.core.resolution.policy import load_resolution_policy

    policy = load_resolution_policy(env_example_settings().RESOLUTION_POLICY_PATH)

    assert policy.policy_version


def test_a_key_that_is_not_a_setting_is_rejected(tmp_path):
    """The behaviour that makes the tests above necessary."""
    env_file = tmp_path / ".env"
    env_file.write_text("ENVIRONMENT=development\nNOT_A_SETTING=1\n", encoding="utf-8")

    with pytest.raises(ValidationError, match="NOT_A_SETTING"):
        Settings(_env_file=env_file)


def test_settings_carry_no_unread_configuration():
    """Every setting is consulted somewhere; a knob that does nothing is a lie."""
    backend = Path(__file__).resolve().parents[1]
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in backend.rglob("*.py")
        if "config.py" not in path.name and ".pytest_cache" not in str(path)
    )

    unread = [name for name in Settings.model_fields if name not in sources]

    assert unread == []
