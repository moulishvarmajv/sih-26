"""Evidence Debt policy: every weight, threshold and expectation, as data.

Nothing in the detectors or the service compares a hard-coded number. What
counts as weak evidence, which corroboration a case is expected to have, how
much a conflict weighs against a stale result — all of it lives in the policy
document, and the version travels with every item and snapshot so an old
snapshot can be explained by the rules that produced it.

Expectations are the part that most needs to be data. "This case is missing a
subscriber register" is a statement about how a particular deployment
investigates, not about evidence; hard-coding one would make the engine assert
something it has no standing to assert.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from app.core.debt.models import (
    DebtBand,
    DebtBlocker,
    DebtCategory,
    DebtSeverity,
)

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_POLICY_PATH = Path(__file__).with_name("debt_policy.json")


class DebtPolicyError(Exception):
    """Raised when an evidence-debt policy document is missing or invalid."""


class ExpectationKind(str, Enum):
    """The shapes of corroboration a policy may require.

    Two, deliberately: a source the case should carry, and an analysis its
    evidence should have. Anything richer is a dependency engine, which this
    phase does not build.
    """

    #: When a trigger source is present in the case, another source is expected.
    SOURCE_PRESENT = "SOURCE_PRESENT"
    #: Each evidence item from a source is expected to have a current result
    #: for a named task type.
    ANALYSIS_PRESENT = "ANALYSIS_PRESENT"


@dataclass(frozen=True)
class CategoryPolicy:
    """One category's weight and what it takes to act on it."""

    weight: float
    blocking_reason: DebtBlocker
    required_capability: str | None
    actionable: bool


@dataclass(frozen=True)
class Expectation:
    """One explicit, configured corroboration rule.

    `expectation_id` is part of the debt item's identity, so renaming a rule
    creates a new item rather than silently rewriting the old one's history.
    """

    expectation_id: str
    kind: ExpectationKind
    when_source_present: str
    severity: DebtSeverity
    expected_source_id: str | None = None
    expected_task_type: str | None = None


@dataclass(frozen=True)
class ResolutionDebtPolicy:
    """How an identity decision's state maps onto debt."""

    unresolved_severity: DebtSeverity
    awaiting_review_severity: DebtSeverity
    deferred_severity: DebtSeverity
    conflict_severity: DebtSeverity
    blocking_conflict_severity: DebtSeverity
    #: Decision statuses whose recorded conflicts still count. A rejected pair
    #: is not in conflict — a person concluded they are different entities, and
    #: the disagreement was the right answer.
    conflict_statuses: frozenset[str]


@dataclass(frozen=True)
class WeakEvidencePolicy:
    """Which trust classifications create debt, and only when relied upon.

    An INFERRED fact is not automatically bad evidence. It becomes debt when the
    case's recorded reasoning rests on it — cited by a finding, or one side of
    an accepted identity link — which is what `requires_material_support` says.
    """

    trust_floor: frozenset[str]
    severity_by_classification: Mapping[str, DebtSeverity]
    requires_material_support: bool


@dataclass(frozen=True)
class ResultConflictRule:
    """A metric an existing analysis result already reports as a disagreement.

    Reusing a computed result rather than re-reading the payload is the point:
    the debt engine must not become a second analyzer.
    """

    task_type: str
    metric: str
    rule: str
    severity: DebtSeverity


@dataclass(frozen=True)
class FindingSupportPolicy:
    no_support_severity: DebtSeverity
    dependency_severity: DebtSeverity
    weak_relationship_severity: DebtSeverity
    #: Which debt categories, found on a finding's supporting evidence, make
    #: that finding's support incomplete.
    dependency_categories: frozenset[DebtCategory]
    #: Signal reason codes that already say the finding rests on something thin.
    weak_relationship_reasons: frozenset[str]


@dataclass(frozen=True)
class ScopePolicy:
    """Maps "how much of the case this touches" into [0, 1]."""

    saturates_at: int
    minimum_factor: float

    def factor(self, affected: int) -> float:
        if self.saturates_at <= 0:
            return 1.0
        raw = min(1.0, max(0, affected) / self.saturates_at)
        return round(max(self.minimum_factor, raw), 6)


@dataclass(frozen=True)
class CriticalityPolicy:
    cited_multiplier: float
    default_multiplier: float

    def factor(self, critical: bool) -> float:
        return self.cited_multiplier if critical else self.default_multiplier


@dataclass(frozen=True)
class DebtLimits:
    """Bounds that keep one case's calculation from becoming unbounded."""

    max_items_per_category: int
    top_items: int


@dataclass(frozen=True)
class DebtBandThreshold:
    band: DebtBand
    minimum_normalized: float


@dataclass(frozen=True)
class EvidenceDebtPolicy:
    policy_version: str
    schema_version: int
    limits: DebtLimits
    categories: Mapping[DebtCategory, CategoryPolicy]
    severity_multipliers: Mapping[DebtSeverity, float]
    scope: ScopePolicy
    criticality: CriticalityPolicy
    normalization_saturates_at: float
    bands: tuple[DebtBandThreshold, ...]  # ordered, highest first
    resolution: ResolutionDebtPolicy
    weak: WeakEvidencePolicy
    stale_severity: DebtSeverity
    result_conflicts: tuple[ResultConflictRule, ...]
    expectations: tuple[Expectation, ...]
    finding_support: FindingSupportPolicy

    def category(self, category: DebtCategory) -> CategoryPolicy:
        try:
            return self.categories[category]
        except KeyError as exc:
            raise DebtPolicyError(f"policy defines no weight for {category.value}") from exc

    def severity_multiplier(self, severity: DebtSeverity) -> float:
        try:
            return self.severity_multipliers[severity]
        except KeyError as exc:
            raise DebtPolicyError(f"policy defines no multiplier for {severity.value}") from exc

    def normalize(self, total: float) -> float:
        """Map a raw total into [0, 1] for display. The raw total is retained."""
        if self.normalization_saturates_at <= 0:
            return 0.0
        return round(min(1.0, max(0.0, total / self.normalization_saturates_at)), 6)

    def band_for(self, normalized: float) -> DebtBand:
        """Bands are ordered highest first, so the first match wins."""
        for threshold in self.bands:
            if normalized >= threshold.minimum_normalized:
                return threshold.band
        return self.bands[-1].band

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> EvidenceDebtPolicy:
        version = document.get("policy_version")
        if not isinstance(version, str) or not version:
            raise DebtPolicyError("debt policy requires a 'policy_version'")

        categories = {}
        for name, entry in _section(document, "categories").items():
            category = _enum(DebtCategory, name, "category")
            if not isinstance(entry, Mapping):
                raise DebtPolicyError(f"category '{name}' must be an object")
            capability = entry.get("required_capability")
            categories[category] = CategoryPolicy(
                weight=_float(entry, "weight", name),
                blocking_reason=_enum(
                    DebtBlocker, entry.get("blocking_reason", "NONE"), "blocking reason"
                ),
                required_capability=None if capability is None else str(capability),
                actionable=bool(entry.get("actionable", False)),
            )
        missing = set(DebtCategory) - set(categories)
        if missing:
            raise DebtPolicyError(
                f"debt policy is missing categories: {sorted(c.value for c in missing)}"
            )

        multipliers = {
            _enum(DebtSeverity, name, "severity"): float(value)
            for name, value in _section(document, "severity_multipliers").items()
        }
        absent = set(DebtSeverity) - set(multipliers)
        if absent:
            raise DebtPolicyError(
                f"debt policy is missing severity multipliers: "
                f"{sorted(s.value for s in absent)}"
            )

        raw_bands = document.get("bands")
        if not isinstance(raw_bands, list) or not raw_bands:
            raise DebtPolicyError("debt policy defines no bands")
        bands = []
        for entry in raw_bands:
            if not isinstance(entry, Mapping):
                raise DebtPolicyError("band entry must be an object")
            bands.append(
                DebtBandThreshold(
                    band=_enum(DebtBand, entry.get("band"), "band"),
                    minimum_normalized=_float(entry, "minimum_normalized", "band"),
                )
            )
        bands.sort(key=lambda threshold: threshold.minimum_normalized, reverse=True)

        return cls(
            policy_version=version,
            schema_version=int(document.get("schema_version", 1)),
            limits=_limits(_section(document, "limits")),
            categories=categories,
            severity_multipliers=multipliers,
            scope=_scope(_section(document, "scope")),
            criticality=_criticality(_section(document, "criticality")),
            normalization_saturates_at=_float(
                _section(document, "normalization"), "saturates_at", "normalization"
            ),
            bands=tuple(bands),
            resolution=_resolution(_section(document, "resolution")),
            weak=_weak(_section(document, "weak")),
            stale_severity=_enum(
                DebtSeverity, _section(document, "stale").get("severity"), "severity"
            ),
            result_conflicts=_result_conflicts(document.get("result_conflicts", [])),
            expectations=_expectations(document.get("expectations", [])),
            finding_support=_finding_support(_section(document, "finding_support")),
        )


def _limits(section: Mapping[str, Any]) -> DebtLimits:
    limits = DebtLimits(
        max_items_per_category=int(section.get("max_items_per_category", 100)),
        top_items=int(section.get("top_items", 10)),
    )
    if limits.max_items_per_category < 1 or limits.top_items < 1:
        raise DebtPolicyError("debt policy limits must be at least 1")
    return limits


def _scope(section: Mapping[str, Any]) -> ScopePolicy:
    scope = ScopePolicy(
        saturates_at=int(section.get("saturates_at", 1)),
        minimum_factor=float(section.get("minimum_factor", 0.0)),
    )
    if scope.saturates_at < 1:
        raise DebtPolicyError("scope.saturates_at must be at least 1")
    if not 0.0 <= scope.minimum_factor <= 1.0:
        raise DebtPolicyError("scope.minimum_factor must be within [0, 1]")
    return scope


def _criticality(section: Mapping[str, Any]) -> CriticalityPolicy:
    return CriticalityPolicy(
        cited_multiplier=_float(section, "cited_multiplier", "criticality"),
        default_multiplier=_float(section, "default_multiplier", "criticality"),
    )


def _resolution(section: Mapping[str, Any]) -> ResolutionDebtPolicy:
    statuses = section.get("conflict_statuses", [])
    if not isinstance(statuses, list) or not all(isinstance(s, str) for s in statuses):
        raise DebtPolicyError("resolution.conflict_statuses must be a list of strings")
    return ResolutionDebtPolicy(
        unresolved_severity=_enum(
            DebtSeverity, section.get("unresolved_severity"), "severity"
        ),
        awaiting_review_severity=_enum(
            DebtSeverity, section.get("awaiting_review_severity"), "severity"
        ),
        deferred_severity=_enum(DebtSeverity, section.get("deferred_severity"), "severity"),
        conflict_severity=_enum(DebtSeverity, section.get("conflict_severity"), "severity"),
        blocking_conflict_severity=_enum(
            DebtSeverity, section.get("blocking_conflict_severity"), "severity"
        ),
        conflict_statuses=frozenset(statuses),
    )


def _weak(section: Mapping[str, Any]) -> WeakEvidencePolicy:
    floor = section.get("trust_floor", [])
    if not isinstance(floor, list) or not all(isinstance(item, str) for item in floor):
        raise DebtPolicyError("weak.trust_floor must be a list of strings")
    severities = section.get("severity_by_classification", {})
    if not isinstance(severities, Mapping):
        raise DebtPolicyError("weak.severity_by_classification must be an object")
    mapped = {
        str(name): _enum(DebtSeverity, value, "severity")
        for name, value in severities.items()
    }
    unmapped = set(floor) - set(mapped)
    if unmapped:
        raise DebtPolicyError(
            f"weak.trust_floor entries have no severity: {sorted(unmapped)}"
        )
    return WeakEvidencePolicy(
        trust_floor=frozenset(floor),
        severity_by_classification=mapped,
        requires_material_support=bool(section.get("requires_material_support", True)),
    )


def _result_conflicts(raw: Any) -> tuple[ResultConflictRule, ...]:
    if not isinstance(raw, list):
        raise DebtPolicyError("result_conflicts must be a list")
    rules = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            raise DebtPolicyError("result_conflicts entry must be an object")
        try:
            rules.append(
                ResultConflictRule(
                    task_type=str(entry["task_type"]),
                    metric=str(entry["metric"]),
                    rule=str(entry["rule"]),
                    severity=_enum(DebtSeverity, entry.get("severity"), "severity"),
                )
            )
        except KeyError as exc:
            raise DebtPolicyError(f"result_conflicts entry is incomplete: {entry!r}") from exc
    return tuple(rules)


def _expectations(raw: Any) -> tuple[Expectation, ...]:
    if not isinstance(raw, list):
        raise DebtPolicyError("expectations must be a list")
    expectations = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, Mapping):
            raise DebtPolicyError("expectation entry must be an object")
        expectation_id = str(entry.get("expectation_id", ""))
        if not expectation_id:
            raise DebtPolicyError("expectation requires an 'expectation_id'")
        if expectation_id in seen:
            raise DebtPolicyError(f"duplicate expectation '{expectation_id}'")
        seen.add(expectation_id)
        kind = _enum(ExpectationKind, entry.get("kind"), "expectation kind")
        trigger = entry.get("when_source_present")
        if not isinstance(trigger, str) or not trigger:
            raise DebtPolicyError(
                f"expectation '{expectation_id}' requires 'when_source_present'"
            )
        expected_source = entry.get("expected_source_id")
        expected_task = entry.get("expected_task_type")
        if kind is ExpectationKind.SOURCE_PRESENT and not expected_source:
            raise DebtPolicyError(
                f"expectation '{expectation_id}' requires 'expected_source_id'"
            )
        if kind is ExpectationKind.ANALYSIS_PRESENT and not expected_task:
            raise DebtPolicyError(
                f"expectation '{expectation_id}' requires 'expected_task_type'"
            )
        expectations.append(
            Expectation(
                expectation_id=expectation_id,
                kind=kind,
                when_source_present=trigger,
                severity=_enum(DebtSeverity, entry.get("severity"), "severity"),
                expected_source_id=None if expected_source is None else str(expected_source),
                expected_task_type=None if expected_task is None else str(expected_task),
            )
        )
    return tuple(expectations)


def _finding_support(section: Mapping[str, Any]) -> FindingSupportPolicy:
    categories = section.get("dependency_categories", [])
    if not isinstance(categories, list):
        raise DebtPolicyError("finding_support.dependency_categories must be a list")
    reasons = section.get("weak_relationship_reasons", [])
    if not isinstance(reasons, list) or not all(isinstance(item, str) for item in reasons):
        raise DebtPolicyError(
            "finding_support.weak_relationship_reasons must be a list of strings"
        )
    return FindingSupportPolicy(
        no_support_severity=_enum(
            DebtSeverity, section.get("no_support_severity"), "severity"
        ),
        dependency_severity=_enum(
            DebtSeverity, section.get("dependency_severity"), "severity"
        ),
        weak_relationship_severity=_enum(
            DebtSeverity, section.get("weak_relationship_severity"), "severity"
        ),
        dependency_categories=frozenset(
            _enum(DebtCategory, name, "category") for name in categories
        ),
        weak_relationship_reasons=frozenset(reasons),
    )


def _section(document: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = document.get(key)
    if not isinstance(value, Mapping):
        raise DebtPolicyError(f"debt policy requires a '{key}' object")
    return value


def _float(section: Mapping[str, Any], key: str, where: str) -> float:
    try:
        return float(section[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise DebtPolicyError(f"'{where}' requires a numeric '{key}'") from exc


def _enum(enum_type, value: Any, what: str):
    try:
        return enum_type(value)
    except ValueError as exc:
        raise DebtPolicyError(f"unknown {what}: {value!r}") from exc


def resolve_policy_path(path: str | Path | None = None) -> Path:
    """Resolve a policy path; relative paths are anchored to the backend root."""
    if path is None:
        from app.core.config import settings

        path = settings.DEBT_POLICY_PATH
    candidate = Path(path)
    return candidate if candidate.is_absolute() else _BACKEND_ROOT / candidate


def load_debt_policy(path: str | Path | None = None) -> EvidenceDebtPolicy:
    policy_path = resolve_policy_path(path)
    try:
        document = json.loads(policy_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DebtPolicyError(f"debt policy not found at {policy_path}") from exc
    except json.JSONDecodeError as exc:
        raise DebtPolicyError(
            f"debt policy at {policy_path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise DebtPolicyError(f"debt policy at {policy_path} must be a JSON object")
    return EvidenceDebtPolicy.from_dict(document)
