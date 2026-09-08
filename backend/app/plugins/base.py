"""AgencyPlugin contract.

One SHADOW-INTEL core; agencies (Police, Cyber Crime, Financial Crime, ...)
are plugins that declare their own entities, relationships, workflows and
policy profile. The core must never branch on agency identity directly —
it only calls through this contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    version: str
    name: str
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    entity_types: tuple[str, ...] = field(default_factory=tuple)
    relationship_types: tuple[str, ...] = field(default_factory=tuple)
    policy_profile: str | None = None


class AgencyPlugin(Protocol):
    manifest: PluginManifest

    def validate(self) -> bool:
        """Return True if the plugin's declared manifest is internally consistent."""
        ...
