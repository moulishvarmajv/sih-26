"""PluginRegistry: discover, validate, register, get, enable/disable AgencyPlugins.

Minimal in-memory implementation. No filesystem plugin discovery yet —
plugins are registered explicitly by whatever wires up the application.
"""
from __future__ import annotations

from app.plugins.base import AgencyPlugin


class PluginRegistryError(Exception):
    pass


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, AgencyPlugin] = {}
        self._enabled: dict[str, bool] = {}

    def register(self, plugin: AgencyPlugin) -> None:
        if not plugin.validate():
            raise PluginRegistryError(f"Plugin '{plugin.manifest.plugin_id}' failed validation")
        plugin_id = plugin.manifest.plugin_id
        if plugin_id in self._plugins:
            raise PluginRegistryError(f"Plugin '{plugin_id}' is already registered")
        self._plugins[plugin_id] = plugin
        self._enabled[plugin_id] = True

    def get(self, plugin_id: str) -> AgencyPlugin | None:
        return self._plugins.get(plugin_id)

    def discover(self) -> tuple[AgencyPlugin, ...]:
        return tuple(self._plugins.values())

    def enable(self, plugin_id: str) -> None:
        self._require_known(plugin_id)
        self._enabled[plugin_id] = True

    def disable(self, plugin_id: str) -> None:
        self._require_known(plugin_id)
        self._enabled[plugin_id] = False

    def is_enabled(self, plugin_id: str) -> bool:
        return self._enabled.get(plugin_id, False)

    def _require_known(self, plugin_id: str) -> None:
        if plugin_id not in self._plugins:
            raise PluginRegistryError(f"Unknown plugin '{plugin_id}'")
