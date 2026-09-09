"""Analytics policy: every threshold, weight, window and limit, as data.

Nothing in the metrics or the service compares a hard-coded number. What counts
as "high connectivity", how wide a temporal window is, how far a path search may
walk — all of it lives in the policy document, and the version travels with
every result so an old signal can be explained by the rules that produced it.

Normalization is part of the policy for a reason. Combining a degree with a
count of entity types means mapping both into [0, 1] first, and the saturation
points that do the mapping are exactly the kind of judgement that should be
visible and adjustable rather than buried in an expression.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_POLICY_PATH = Path(__file__).with_name("analytics_policy.json")


class AnalyticsPolicyError(Exception):
    """Raised when an analytics policy document is missing or invalid."""


@dataclass(frozen=True)
class Limits:
    """Bounds that keep one case's analytics from becoming an unbounded query."""

    max_relationships: int
    max_path_length: int
    max_signals_per_type: int
    max_component_members: int


@dataclass(frozen=True)
class ConnectivityPolicy:
    minimum_degree: int
    top_n: int
    weights: Mapping[str, float]
    normalization: Mapping[str, float]


@dataclass(frozen=True)
class BridgePolicy:
    minimum_groups_connected: int
    minimum_entity_types: int
    weak_relationship_duration_seconds: int
    weights: Mapping[str, float]
    normalization: Mapping[str, float]


@dataclass(frozen=True)
class ComponentPolicy:
    minimum_members: int
    isolated_maximum_members: int


@dataclass(frozen=True)
class TemporalPolicy:
    window_seconds: int
    minimum_events_in_window: int
    concentration_multiple: float
    weights: Mapping[str, float]
    normalization: Mapping[str, float]


@dataclass(frozen=True)
class ConfidenceBand:
    band: str
    minimum_score: float


@dataclass(frozen=True)
class AnalyticsPolicy:
    analytics_version: str
    schema_version: int
    limits: Limits
    connectivity: ConnectivityPolicy
    bridge: BridgePolicy
    components: ComponentPolicy
    temporal: TemporalPolicy
    confidence_bands: tuple[ConfidenceBand, ...]  # ordered, highest first

    def band_for(self, score: float) -> ConfidenceBand:
        """The band a score falls in. Bands are ordered, so the first match wins."""
        for band in self.confidence_bands:
            if score >= band.minimum_score:
                return band
        return self.confidence_bands[-1]

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> AnalyticsPolicy:
        version = document.get("analytics_version")
        if not isinstance(version, str) or not version:
            raise AnalyticsPolicyError("analytics policy requires an 'analytics_version'")

        limits = _section(document, "limits")
        connectivity = _section(document, "connectivity")
        bridge = _section(document, "bridge")
        components = _section(document, "components")
        temporal = _section(document, "temporal")

        raw_bands = document.get("confidence_bands")
        if not isinstance(raw_bands, list) or not raw_bands:
            raise AnalyticsPolicyError("analytics policy defines no confidence bands")
        bands = []
        for entry in raw_bands:
            if not isinstance(entry, Mapping):
                raise AnalyticsPolicyError("confidence band entry must be an object")
            try:
                bands.append(
                    ConfidenceBand(
                        band=str(entry["band"]),
                        minimum_score=float(entry["minimum_score"]),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise AnalyticsPolicyError(f"invalid confidence band: {entry!r}") from exc
        bands.sort(key=lambda band: band.minimum_score, reverse=True)

        try:
            parsed_limits = Limits(
                max_relationships=int(limits["max_relationships"]),
                max_path_length=int(limits["max_path_length"]),
                max_signals_per_type=int(limits["max_signals_per_type"]),
                max_component_members=int(limits["max_component_members"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AnalyticsPolicyError("analytics policy has incomplete limits") from exc
        if parsed_limits.max_path_length < 1:
            raise AnalyticsPolicyError("max_path_length must be at least 1")
        if parsed_limits.max_relationships < 1:
            raise AnalyticsPolicyError("max_relationships must be at least 1")

        return cls(
            analytics_version=version,
            schema_version=int(document.get("schema_version", 1)),
            limits=parsed_limits,
            connectivity=ConnectivityPolicy(
                minimum_degree=int(connectivity.get("minimum_degree", 1)),
                top_n=int(connectivity.get("top_n", 10)),
                weights=_floats(connectivity, "weights"),
                normalization=_floats(connectivity, "normalization"),
            ),
            bridge=BridgePolicy(
                minimum_groups_connected=int(bridge.get("minimum_groups_connected", 2)),
                minimum_entity_types=int(bridge.get("minimum_entity_types", 2)),
                weak_relationship_duration_seconds=int(
                    bridge.get("weak_relationship_duration_seconds", 0)
                ),
                weights=_floats(bridge, "weights"),
                normalization=_floats(bridge, "normalization"),
            ),
            components=ComponentPolicy(
                minimum_members=int(components.get("minimum_members", 2)),
                isolated_maximum_members=int(components.get("isolated_maximum_members", 3)),
            ),
            temporal=TemporalPolicy(
                window_seconds=int(temporal.get("window_seconds", 3600)),
                minimum_events_in_window=int(temporal.get("minimum_events_in_window", 3)),
                concentration_multiple=float(temporal.get("concentration_multiple", 2.0)),
                weights=_floats(temporal, "weights"),
                normalization=_floats(temporal, "normalization"),
            ),
            confidence_bands=tuple(bands),
        )


def _section(document: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = document.get(key)
    if not isinstance(value, Mapping):
        raise AnalyticsPolicyError(f"analytics policy requires a '{key}' object")
    return value


def _floats(section: Mapping[str, Any], key: str) -> Mapping[str, float]:
    raw = section.get(key, {})
    if not isinstance(raw, Mapping):
        raise AnalyticsPolicyError(f"'{key}' must be an object")
    return {str(name): float(value) for name, value in raw.items()}


def resolve_policy_path(path: str | Path | None = None) -> Path:
    """Resolve a policy path; relative paths are anchored to the backend root."""
    if path is None:
        from app.core.config import settings

        path = settings.ANALYTICS_POLICY_PATH
    candidate = Path(path)
    return candidate if candidate.is_absolute() else _BACKEND_ROOT / candidate


def load_analytics_policy(path: str | Path | None = None) -> AnalyticsPolicy:
    policy_path = resolve_policy_path(path)
    try:
        document = json.loads(policy_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AnalyticsPolicyError(f"analytics policy not found at {policy_path}") from exc
    except json.JSONDecodeError as exc:
        raise AnalyticsPolicyError(
            f"analytics policy at {policy_path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise AnalyticsPolicyError(f"analytics policy at {policy_path} must be a JSON object")
    return AnalyticsPolicy.from_dict(document)
