"""PluginRegistry can register, discover, and enable/disable an AgencyPlugin contract."""
import pytest

from app.plugins.base import PluginManifest
from app.plugins.registry import PluginRegistry, PluginRegistryError


class _FakePlugin:
    manifest = PluginManifest(plugin_id="test-agency", version="0.1.0", name="Test Agency")

    def validate(self) -> bool:
        return True


def test_register_and_discover():
    registry = PluginRegistry()
    plugin = _FakePlugin()

    registry.register(plugin)

    assert registry.get("test-agency") is plugin
    assert plugin in registry.discover()
    assert registry.is_enabled("test-agency") is True


def test_disable_and_enable():
    registry = PluginRegistry()
    registry.register(_FakePlugin())

    registry.disable("test-agency")
    assert registry.is_enabled("test-agency") is False

    registry.enable("test-agency")
    assert registry.is_enabled("test-agency") is True


def test_register_failing_validation_raises():
    class _InvalidPlugin(_FakePlugin):
        def validate(self) -> bool:
            return False

    registry = PluginRegistry()
    with pytest.raises(PluginRegistryError):
        registry.register(_InvalidPlugin())


def test_duplicate_registration_raises():
    registry = PluginRegistry()
    registry.register(_FakePlugin())

    with pytest.raises(PluginRegistryError):
        registry.register(_FakePlugin())
