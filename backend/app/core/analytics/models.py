"""Investigation signal domain model.

A signal is an observation about the *shape* of a case graph: which entities sit
between otherwise separate groups, which are unusually well connected, which
events cluster in time. It is a place to look, not a conclusion — and the
vocabulary is chosen so that it cannot be read as one. There is no signal type,
reason code or field here that describes a person's conduct, and a test asserts
that stays true.

Three rules the model exists to enforce:

- **An entity is identified by a hash, never by its key.** The raw key is a
  phone number or an IMEI; `AnalyticsEntity.entity_id` is the same opaque id the
  graph API returns, so a signal about a masked entity discloses nothing while
  still being a stable thing to click on.
- **A score is never a bare number.** Every score carries the metrics, weights
  and contributions it was built from, so "why did this rank first?" is
  answerable from the record alone.
- **A signal names its evidence.** Supporting relationship and evidence ids
  travel with it, so any claim can be traced back to what was observed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SignalType(str, Enum):
    """What kind of structure was observed. Never what it means about anyone."""

    HIGH_CONNECTIVITY = "HIGH_CONNECTIVITY"
    CROSS_DOMAIN_BRIDGE = "CROSS_DOMAIN_BRIDGE"
    COMPONENT_STRUCTURE = "COMPONENT_STRUCTURE"
    TEMPORAL_CONCENTRATION = "TEMPORAL_CONCENTRATION"
    SHORTEST_PATH = "SHORTEST_PATH"


class SignalStatus(str, Enum):
    #: The current result for this signal's identity within its case.
    ACTIVE = "ACTIVE"
    #: A later analytics run produced a different result; kept, never deleted.
    SUPERSEDED = "SUPERSEDED"


class SignalReason(str, Enum):
    """Machine-stable explanations. Rendered by a client, never parsed as prose."""

    DEGREE_ABOVE_THRESHOLD = "DEGREE_ABOVE_THRESHOLD"
    TOP_RANKED_CONNECTIVITY = "TOP_RANKED_CONNECTIVITY"
    CONNECTS_SEPARATE_GROUPS = "CONNECTS_SEPARATE_GROUPS"
    SPANS_MULTIPLE_ENTITY_TYPES = "SPANS_MULTIPLE_ENTITY_TYPES"
    REMOVAL_SEPARATES_GRAPH = "REMOVAL_SEPARATES_GRAPH"
    #: The connection rests on one low-weight relationship. Recorded *with* a
    #: bridge signal, because structure alone does not establish that two groups
    #: are meaningfully connected — a single zero-second call looks identical to
    #: a real link until someone reads the evidence.
    RESTS_ON_SINGLE_WEAK_RELATIONSHIP = "RESTS_ON_SINGLE_WEAK_RELATIONSHIP"
    EVENTS_CONCENTRATED_IN_WINDOW = "EVENTS_CONCENTRATED_IN_WINDOW"
    COMPONENT_IS_ISOLATED = "COMPONENT_IS_ISOLATED"
    PATH_FOUND = "PATH_FOUND"
    NO_PATH_WITHIN_LIMIT = "NO_PATH_WITHIN_LIMIT"


@dataclass(frozen=True)
class AnalyticsEntity:
    """One entity as analytics may disclose it.

    `entity_id` is the hashed graph node id and `label` has already been through
    the privacy policy. The natural key never reaches this type, so it cannot
    reach a response.
    """

    entity_id: str
    entity_type: str
    label: str


@dataclass(frozen=True)
class SignalMetric:
    """One input to a score, with the weight that was applied to it.

    `value` is the raw measurement (a degree, a count of groups). `normalized`
    is that value mapped into [0, 1] so unlike metrics can be combined, and
    `contribution` is `normalized * weight` — the number that actually moved the
    score.
    """

    name: str
    value: float
    normalized: float
    weight: float
    contribution: float


@dataclass(frozen=True)
class InvestigationSignal:
    """One observation about the shape of a case graph."""

    signal_id: str
    case_id: str
    signal_type: SignalType
    entities: tuple[AnalyticsEntity, ...]
    score: float
    confidence: str
    reasons: tuple[SignalReason, ...]
    metrics: tuple[SignalMetric, ...]
    supporting_relationship_ids: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    created_at: str
    analytics_version: str
    run_id: str
    #: `signal_id` is the identity of "this observation, about these entities,
    #: in this case" and is stable across runs. `version` distinguishes what
    #: successive runs concluded about it, so history is kept rather than
    #: overwritten.
    version: int = 1
    status: SignalStatus = SignalStatus.ACTIVE
    #: Structured detail specific to the signal type — a component's entity
    #: counts, a window's bounds. Primitives only, and never a resource value.
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def entity_ids(self) -> tuple[str, ...]:
        return tuple(entity.entity_id for entity in self.entities)


@dataclass(frozen=True)
class AnalyticsRun:
    """One execution, and the scope it saw.

    The scope matters as much as the result: a signal computed over four
    authorized evidence items is not comparable with one computed over nine, and
    a reader with narrower access legitimately gets a different answer.
    """

    run_id: str
    case_id: str
    analytics_version: str
    executed_at: str
    executed_by: str
    correlation_id: str
    evidence_ids: tuple[str, ...]
    node_count: int
    relationship_count: int
    signal_count: int
    excluded_evidence_count: int
    truncated: bool = False


@dataclass(frozen=True)
class PathStep:
    """One hop of a path: the relationship traversed and where it led."""

    relationship_id: str
    relationship_type: str
    from_entity: AnalyticsEntity
    to_entity: AnalyticsEntity
    evidence_id: str
    observed_at: str


@dataclass(frozen=True)
class EntityPath:
    """An ordered walk between two entities, or the absence of one."""

    case_id: str
    source: AnalyticsEntity
    target: AnalyticsEntity
    steps: tuple[PathStep, ...]
    length: int
    found: bool
    max_length_searched: int
    reason: SignalReason
    analytics_version: str

    @property
    def entities(self) -> tuple[AnalyticsEntity, ...]:
        if not self.steps:
            return ()
        return (self.steps[0].from_entity,) + tuple(step.to_entity for step in self.steps)

    @property
    def relationship_ids(self) -> tuple[str, ...]:
        return tuple(step.relationship_id for step in self.steps)

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(sorted({step.evidence_id for step in self.steps if step.evidence_id}))


@dataclass(frozen=True)
class ConnectivityMetric:
    """Degree measurements for one entity, with its standing in the case."""

    entity: AnalyticsEntity
    degree: int
    in_degree: int
    out_degree: int
    distinct_neighbours: int
    entity_types_touched: tuple[str, ...]
    rank: int
    rank_of: int
    supporting_relationship_ids: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class GraphComponent:
    """One connected group within the authorized case graph."""

    component_id: str
    members: tuple[AnalyticsEntity, ...]
    entity_count: int
    relationship_count: int
    entity_type_counts: dict[str, int]
    dominant_entity_type: str
    supporting_evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class BridgeMetric:
    """An entity that holds otherwise separate parts of the graph together.

    `group_sizes` is the explanation: removing this entity leaves its
    neighbourhood in this many pieces, of these sizes, with no route between
    them in the authorized graph.
    """

    entity: AnalyticsEntity
    groups_separated: int
    group_sizes: tuple[int, ...]
    #: The size of the largest region this entity cuts off from the main body.
    #: A bridge holding two substantial groups apart is a different finding from
    #: one holding a single entity that happens to hang off it, and ranking has
    #: to tell them apart.
    separated_side_size: int
    entity_types_spanned: tuple[str, ...]
    neighbour_count: int
    rests_on_weak_relationship: bool
    supporting_relationship_ids: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class TemporalWindow:
    """A bucket of observed events, and how it compares with the case's average."""

    window_start: str
    window_end: str
    event_count: int
    mean_event_count: float
    concentration_ratio: float
    supporting_relationship_ids: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def signal_identity(case_id: str, signal_type: SignalType, *subjects: str) -> str:
    """Stable identity for "this signal, about these entities, in this case".

    Deterministic rather than random so a re-run recognises the signal it
    already produced and supersedes it, instead of accumulating duplicates that
    look like new findings.
    """
    return f"SIG-{_digest(case_id, signal_type.value, *sorted(subjects))[:16].upper()}"


def run_identity(case_id: str, analytics_version: str, executed_at: str, scope: str) -> str:
    return f"ARUN-{_digest(case_id, analytics_version, executed_at, scope)[:16].upper()}"


def explain(signal: InvestigationSignal) -> dict[str, Any]:
    """Machine-readable explanation of one signal. No prose, no resource values."""
    return {
        "signal_type": signal.signal_type.value,
        "score": round(signal.score, 4),
        "confidence": signal.confidence,
        "analytics_version": signal.analytics_version,
        "reasons": [reason.value for reason in signal.reasons],
        "metrics": [
            {
                "name": metric.name,
                "value": round(metric.value, 4),
                "normalized": round(metric.normalized, 4),
                "weight": round(metric.weight, 4),
                "contribution": round(metric.contribution, 4),
            }
            for metric in signal.metrics
        ],
        "supporting_relationship_ids": list(signal.supporting_relationship_ids),
        "supporting_evidence_ids": list(signal.supporting_evidence_ids),
        "detail": dict(signal.detail),
    }
