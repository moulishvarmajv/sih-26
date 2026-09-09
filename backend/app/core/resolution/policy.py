"""Resolution policy: every weight, threshold and rule that decides a match.

Policy is *data*. Nothing in the scorer, the candidate generator or the service
compares a hard-coded number: they ask this policy. Swapping the document
changes matching behaviour without touching code, and the version string travels
with every decision so an old outcome can always be explained by the rules that
produced it.

There is deliberately no single universal threshold. Thresholds are per entity
type, and four of them work together:

    auto_accept              a score at or above this may be asserted without a human
    review_floor             below this the pair is recorded but nothing is asserted
    minimum_evidence_weight  how much had to be *comparable* before auto-accepting
    ambiguity_margin         how close a rival candidate may be before both go to review

The last two exist because a score alone is not enough. Agreement on one weak
attribute scores the same as agreement on six strong ones, and two candidates
scoring 0.91 and 0.89 are not a decision — they are a question for a person.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from app.core.resolution.models import BlockingStrategy, ConfidenceBand, EntityType, MatchSignal

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_POLICY_PATH = Path(__file__).with_name("resolution_policy.json")


class ResolutionPolicyError(Exception):
    """Raised when a resolution policy document is missing or invalid."""


@dataclass(frozen=True)
class SignalRule:
    signal: MatchSignal
    attribute: str
    weight: float
    minimum_similarity: float | None = None
    maximum_gap_days: int | None = None


@dataclass(frozen=True)
class ConflictRule:
    attribute: str
    rule: str
    penalty: float
    blocks_auto_accept: bool
    maximum_similarity: float | None = None


@dataclass(frozen=True)
class Thresholds:
    auto_accept: float
    review_floor: float
    ambiguity_margin: float
    minimum_evidence_weight: float


@dataclass(frozen=True)
class ConfidenceBandSpec:
    band: ConfidenceBand
    minimum_score: float


@dataclass(frozen=True)
class EntityTypePolicy:
    entity_type: EntityType
    blocking: tuple[BlockingStrategy, ...]
    signals: Mapping[MatchSignal, SignalRule]
    conflicts: Mapping[str, ConflictRule]
    thresholds: Thresholds
    confidence_bands: tuple[ConfidenceBandSpec, ...]  # ordered, highest first

    @property
    def total_weight(self) -> float:
        return sum(rule.weight for rule in self.signals.values())

    def signal(self, signal: MatchSignal) -> SignalRule | None:
        return self.signals.get(signal)

    def band_for(self, score: float) -> ConfidenceBandSpec:
        """The band a score falls in. Bands are ordered, so the first match wins."""
        for spec in self.confidence_bands:
            if score >= spec.minimum_score:
                return spec
        return self.confidence_bands[-1]


@dataclass(frozen=True)
class ResolutionPolicy:
    policy_version: str
    schema_version: int
    entity_types: Mapping[EntityType, EntityTypePolicy]
    source_reliability: Mapping[str, float]
    default_source_reliability: float

    def for_entity(self, entity_type: EntityType) -> EntityTypePolicy:
        try:
            return self.entity_types[entity_type]
        except KeyError as exc:
            raise ResolutionPolicyError(
                f"no resolution policy for entity type '{entity_type.value}'"
            ) from exc

    def reliability_of(self, source_id: str) -> float:
        """Unknown sources fall back to the configured default, never to 1.0."""
        return self.source_reliability.get(source_id, self.default_source_reliability)

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> ResolutionPolicy:
        policy_version = document.get("policy_version")
        if not isinstance(policy_version, str) or not policy_version:
            raise ResolutionPolicyError("resolution policy requires a 'policy_version'")

        raw_types = document.get("entity_types")
        if not isinstance(raw_types, Mapping) or not raw_types:
            raise ResolutionPolicyError("resolution policy defines no entity types")

        entity_types: dict[EntityType, EntityTypePolicy] = {}
        for raw_name, raw_policy in raw_types.items():
            try:
                entity_type = EntityType(raw_name)
            except ValueError as exc:
                raise ResolutionPolicyError(f"unknown entity type '{raw_name}'") from exc
            entity_types[entity_type] = _entity_policy(entity_type, raw_policy)

        reliability = document.get("source_reliability", {})
        if not isinstance(reliability, Mapping):
            raise ResolutionPolicyError("'source_reliability' must be an object")
        default = reliability.get("default")
        if not isinstance(default, (int, float)):
            raise ResolutionPolicyError("'source_reliability' requires a 'default'")

        return cls(
            policy_version=policy_version,
            schema_version=int(document.get("schema_version", 1)),
            entity_types=entity_types,
            source_reliability={
                key: float(value)
                for key, value in reliability.items()
                if key != "default" and isinstance(value, (int, float))
            },
            default_source_reliability=float(default),
        )


def _entity_policy(entity_type: EntityType, raw: Any) -> EntityTypePolicy:
    if not isinstance(raw, Mapping):
        raise ResolutionPolicyError(f"policy for '{entity_type.value}' must be an object")

    signals: dict[MatchSignal, SignalRule] = {}
    for raw_signal, raw_rule in _mapping(raw, "signals", entity_type).items():
        try:
            signal = MatchSignal(raw_signal)
        except ValueError as exc:
            raise ResolutionPolicyError(f"unknown match signal '{raw_signal}'") from exc
        if not isinstance(raw_rule, Mapping) or "weight" not in raw_rule:
            raise ResolutionPolicyError(f"signal '{raw_signal}' requires a weight")
        signals[signal] = SignalRule(
            signal=signal,
            attribute=str(raw_rule.get("attribute", raw_signal.lower())),
            weight=float(raw_rule["weight"]),
            minimum_similarity=_optional_float(raw_rule.get("minimum_similarity")),
            maximum_gap_days=_optional_int(raw_rule.get("maximum_gap_days")),
        )
    if not signals:
        raise ResolutionPolicyError(f"policy for '{entity_type.value}' defines no signals")

    conflicts: dict[str, ConflictRule] = {}
    for attribute, raw_conflict in _mapping(raw, "conflicts", entity_type).items():
        if not isinstance(raw_conflict, Mapping):
            raise ResolutionPolicyError(f"conflict '{attribute}' must be an object")
        conflicts[str(attribute)] = ConflictRule(
            attribute=str(attribute),
            rule=str(raw_conflict.get("rule", f"DIFFERENT_{str(attribute).upper()}")),
            penalty=float(raw_conflict.get("penalty", 0.0)),
            blocks_auto_accept=bool(raw_conflict.get("blocks_auto_accept", False)),
            maximum_similarity=_optional_float(raw_conflict.get("maximum_similarity")),
        )

    raw_thresholds = _mapping(raw, "thresholds", entity_type)
    try:
        thresholds = Thresholds(
            auto_accept=float(raw_thresholds["auto_accept"]),
            review_floor=float(raw_thresholds["review_floor"]),
            ambiguity_margin=float(raw_thresholds["ambiguity_margin"]),
            minimum_evidence_weight=float(raw_thresholds["minimum_evidence_weight"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ResolutionPolicyError(
            f"policy for '{entity_type.value}' has incomplete thresholds"
        ) from exc
    if thresholds.review_floor > thresholds.auto_accept:
        raise ResolutionPolicyError(
            f"policy for '{entity_type.value}' has review_floor above auto_accept"
        )

    raw_bands = raw.get("confidence_bands")
    if not isinstance(raw_bands, list) or not raw_bands:
        raise ResolutionPolicyError(f"policy for '{entity_type.value}' defines no confidence bands")
    bands: list[ConfidenceBandSpec] = []
    for entry in raw_bands:
        if not isinstance(entry, Mapping):
            raise ResolutionPolicyError("confidence band entry must be an object")
        try:
            bands.append(
                ConfidenceBandSpec(
                    band=ConfidenceBand(entry["band"]),
                    minimum_score=float(entry["minimum_score"]),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ResolutionPolicyError(f"invalid confidence band entry: {entry!r}") from exc
    bands.sort(key=lambda spec: spec.minimum_score, reverse=True)

    blocking: list[BlockingStrategy] = []
    for raw_strategy in raw.get("blocking", []):
        try:
            blocking.append(BlockingStrategy(raw_strategy))
        except ValueError as exc:
            raise ResolutionPolicyError(f"unknown blocking strategy '{raw_strategy}'") from exc
    if not blocking:
        raise ResolutionPolicyError(
            f"policy for '{entity_type.value}' defines no blocking strategies"
        )

    return EntityTypePolicy(
        entity_type=entity_type,
        blocking=tuple(blocking),
        signals=signals,
        conflicts=conflicts,
        thresholds=thresholds,
        confidence_bands=tuple(bands),
    )


def _mapping(raw: Mapping[str, Any], key: str, entity_type: EntityType) -> Mapping[str, Any]:
    value = raw.get(key, {})
    if not isinstance(value, Mapping):
        raise ResolutionPolicyError(f"'{key}' for '{entity_type.value}' must be an object")
    return value


def _optional_float(value: Any) -> float | None:
    return None if value is None else float(value)


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def resolve_policy_path(path: str | Path | None = None) -> Path:
    """Resolve a policy path; relative paths are anchored to the backend root."""
    if path is None:
        from app.core.config import settings

        path = settings.RESOLUTION_POLICY_PATH
    candidate = Path(path)
    return candidate if candidate.is_absolute() else _BACKEND_ROOT / candidate


def load_resolution_policy(path: str | Path | None = None) -> ResolutionPolicy:
    policy_path = resolve_policy_path(path)
    try:
        document = json.loads(policy_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ResolutionPolicyError(f"resolution policy not found at {policy_path}") from exc
    except json.JSONDecodeError as exc:
        raise ResolutionPolicyError(
            f"resolution policy at {policy_path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise ResolutionPolicyError(f"resolution policy at {policy_path} must be a JSON object")
    return ResolutionPolicy.from_dict(document)
