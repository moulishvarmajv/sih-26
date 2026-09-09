"""Evidence Debt domain model.

Evidence Debt measures how much of what an investigation currently *knows*
rests on evidence that is unresolved, weak, conflicting, missing, stale, or
waiting on a person. It is an investigation-quality metric and nothing else.

What it is not, stated here because the number will be read by people who did
not build it: it is not guilt, not a probability of criminality or conviction,
not a completion percentage, and not a measure of an investigator. A HIGH band
means the case has support gaps — the same case can be legally strong and carry
high debt, and a case with no debt can be worthless.

Three rules the model exists to enforce:

- **A debt item names field names and identifiers, never resource values.** An
  entity is a hashed `entity_ref`, an attribute is its name. A debt explanation
  that quoted a phone number would hand back what a PARTIAL decision masked.
- **A contribution is never a bare number.** Every item carries the four
  factors it was built from — category weight, severity, affected scope,
  criticality — so "why is this case HIGH?" is answerable from the record.
- **An item's identity is a fingerprint of what it is about, not of when it was
  found.** The same gap detected on Monday and Friday is one debt item with two
  versions, not two findings.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

#: The calculation code's own version, distinct from the policy document's.
#: Both travel with every item and snapshot: a number is only explainable if
#: you know which rules *and* which weights produced it.
DEBT_ENGINE_VERSION = "debt-engine-1.0.0"


class DebtCategory(str, Enum):
    """What kind of gap this is. Seven, and no catch-all `OTHER`."""

    #: An identity question the system compared and could not settle, and that
    #: is not in anyone's queue.
    UNRESOLVED = "UNRESOLVED"
    #: Evidence that disagrees with other evidence on a material attribute.
    CONFLICTING = "CONFLICTING"
    #: Reasoning resting on evidence below the policy's trust floor.
    WEAK = "WEAK"
    #: Corroboration the policy expects for this case and that is not there.
    MISSING = "MISSING"
    #: A result computed from a version that has since been superseded.
    STALE = "STALE"
    #: An outstanding human decision.
    HUMAN_REVIEW = "HUMAN_REVIEW"
    #: A recorded finding whose support is incomplete or itself in debt.
    UNSUPPORTED_FINDING = "UNSUPPORTED_FINDING"


class DebtSeverity(str, Enum):
    """How much one item of a category weighs. Multipliers live in policy."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DebtStatus(str, Enum):
    """The item's lifecycle. Nothing here is ever deleted."""

    OPEN = "OPEN"
    #: A person has seen it and accepted that it stands for now. A later
    #: recalculation inherits this rather than reopening it, so automation
    #: never erases an investigator's judgement.
    ACKNOWLEDGED = "ACKNOWLEDGED"
    #: The gap is gone: a recalculation no longer detects it.
    RESOLVED = "RESOLVED"
    #: The facts changed and a newer version of this item replaced it.
    SUPERSEDED = "SUPERSEDED"


class DebtBand(str, Enum):
    """A case's debt level. Thresholds are policy, never compared in code."""

    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DebtSubjectType(str, Enum):
    """What the item is about, which decides how a client can navigate to it."""

    EVIDENCE = "EVIDENCE"
    ANALYSIS_RESULT = "ANALYSIS_RESULT"
    RESOLUTION = "RESOLUTION"
    SIGNAL = "SIGNAL"
    EXPECTATION = "EXPECTATION"
    CASE = "CASE"


class DebtReason(str, Enum):
    """Machine-stable explanations. Rendered by a client, never parsed as prose."""

    # Unresolved / human review
    RESOLUTION_BELOW_REVIEW_FLOOR = "RESOLUTION_BELOW_REVIEW_FLOOR"
    RESOLUTION_AWAITING_REVIEW = "RESOLUTION_AWAITING_REVIEW"
    RESOLUTION_REVIEW_DEFERRED = "RESOLUTION_REVIEW_DEFERRED"
    # Conflict
    RESOLUTION_ATTRIBUTE_CONFLICT = "RESOLUTION_ATTRIBUTE_CONFLICT"
    RESOLUTION_CONFLICT_BLOCKS_ACCEPTANCE = "RESOLUTION_CONFLICT_BLOCKS_ACCEPTANCE"
    OBSERVATIONS_DISAGREE_WITHIN_EVIDENCE = "OBSERVATIONS_DISAGREE_WITHIN_EVIDENCE"
    # Weak support
    SUPPORTING_EVIDENCE_BELOW_TRUST_FLOOR = "SUPPORTING_EVIDENCE_BELOW_TRUST_FLOOR"
    # Missing
    EXPECTED_SOURCE_ABSENT = "EXPECTED_SOURCE_ABSENT"
    EXPECTED_ANALYSIS_ABSENT = "EXPECTED_ANALYSIS_ABSENT"
    # Stale
    RESULT_COMPUTED_FROM_SUPERSEDED_VERSION = "RESULT_COMPUTED_FROM_SUPERSEDED_VERSION"
    # Finding support
    FINDING_HAS_NO_SUPPORTING_EVIDENCE = "FINDING_HAS_NO_SUPPORTING_EVIDENCE"
    FINDING_DEPENDS_ON_UNRESOLVED_ENTITY = "FINDING_DEPENDS_ON_UNRESOLVED_ENTITY"
    FINDING_DEPENDS_ON_CONFLICTING_EVIDENCE = "FINDING_DEPENDS_ON_CONFLICTING_EVIDENCE"
    FINDING_DEPENDS_ON_WEAK_EVIDENCE = "FINDING_DEPENDS_ON_WEAK_EVIDENCE"
    FINDING_DEPENDS_ON_STALE_ANALYSIS = "FINDING_DEPENDS_ON_STALE_ANALYSIS"
    FINDING_RESTS_ON_SINGLE_WEAK_RELATIONSHIP = "FINDING_RESTS_ON_SINGLE_WEAK_RELATIONSHIP"


class DebtBlocker(str, Enum):
    """What has to happen before an item can close.

    Structured for a later Navigator to consume. This phase records it; nothing
    here recommends, ranks for a person, or acts.
    """

    #: Nothing external: whoever holds the capability can act now.
    NONE = "NONE"
    AWAITING_HUMAN_REVIEW = "AWAITING_HUMAN_REVIEW"
    AWAITING_ADDITIONAL_EVIDENCE = "AWAITING_ADDITIONAL_EVIDENCE"
    AWAITING_REANALYSIS = "AWAITING_REANALYSIS"
    AWAITING_ENTITY_RESOLUTION = "AWAITING_ENTITY_RESOLUTION"


@dataclass(frozen=True)
class DebtSubject:
    """What one item is about.

    `reference` is an id inside this platform (an evidence id, a resolution id,
    an expectation id). `entity_refs` are the hashed entity ids resolution and
    the graph already use — never a natural key, so a subject cannot disclose an
    identifier a reader is not cleared for.
    """

    subject_type: DebtSubjectType
    reference: str
    entity_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class DebtWeighting:
    """The four factors behind one item's contribution, and the product.

    Kept as an explicit type rather than a float on the item, because a debt
    total nobody can decompose is exactly the opaque "72% complete" number this
    subsystem exists to avoid.
    """

    category_weight: float
    severity_multiplier: float
    #: How much of the case this item touches, mapped into [0, 1] by the
    #: policy's saturation point. `affected_scope` is the raw count behind it.
    scope_factor: float
    #: Whether the affected evidence is something the case's reasoning actually
    #: rests on — cited by a recorded finding or an accepted identity link.
    criticality_factor: float
    affected_scope: int
    weighted_contribution: float

    def explain(self) -> dict[str, float | int]:
        return {
            "category_weight": round(self.category_weight, 6),
            "severity_multiplier": round(self.severity_multiplier, 6),
            "scope_factor": round(self.scope_factor, 6),
            "criticality_factor": round(self.criticality_factor, 6),
            "affected_scope": self.affected_scope,
            "weighted_contribution": round(self.weighted_contribution, 6),
        }


@dataclass(frozen=True)
class EvidenceDebtItem:
    """One named gap in what the investigation can currently support.

    `explanation` is a machine-readable map of field *names*, ids, counts and
    rule names. It never carries a resource value, and a test asserts that.
    """

    debt_id: str
    case_id: str
    category: DebtCategory
    severity: DebtSeverity
    status: DebtStatus
    reason: DebtReason
    subject: DebtSubject
    weighting: DebtWeighting
    explanation: Mapping[str, Any]
    supporting_evidence_ids: tuple[str, ...]
    related_resolution_ids: tuple[str, ...]
    related_finding_ids: tuple[str, ...]
    created_at: str
    calculated_at: str
    policy_version: str
    debt_engine_version: str
    #: What a later Navigator needs and this phase records without acting on.
    actionable: bool
    priority: int
    blocking_reason: DebtBlocker
    required_capability: str | None
    #: The authorized evidence scope this item was detected in. `debt_id`
    #: identifies the gap itself and is the same for everyone who can see it;
    #: the persisted *record* belongs to a scope, so a narrow reader can never
    #: read, close or overwrite a record built over evidence they cannot see.
    scope_fingerprint: str
    #: The item's identity is stable; `version` distinguishes what successive
    #: calculations concluded about it, so history is kept rather than replaced.
    version: int = 1
    fact_fingerprint: str = ""
    status_changed_at: str | None = None
    status_changed_by: str | None = None
    status_reason: str | None = None

    @property
    def contribution(self) -> float:
        return self.weighting.weighted_contribution

    def explain(self) -> dict[str, Any]:
        """Machine-readable explanation of one item. No prose, no values."""
        return {
            "debt_id": self.debt_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "reason": self.reason.value,
            "subject_type": self.subject.subject_type.value,
            "subject_reference": self.subject.reference,
            "entity_refs": list(self.subject.entity_refs),
            "weighting": self.weighting.explain(),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "related_resolution_ids": list(self.related_resolution_ids),
            "related_finding_ids": list(self.related_finding_ids),
            "detail": dict(self.explanation),
            "actionable": self.actionable,
            "priority": self.priority,
            "blocking_reason": self.blocking_reason.value,
            "required_capability": self.required_capability,
            "policy_version": self.policy_version,
            "debt_engine_version": self.debt_engine_version,
        }


@dataclass(frozen=True)
class EvidenceDebtBreakdown:
    """One category's share of a snapshot.

    Every category is reported, including the ones scoring zero: a breakdown
    that omitted empty categories would make "no conflicts found" and "conflicts
    not looked for" indistinguishable.
    """

    category: DebtCategory
    item_count: int
    weighted_contribution: float
    #: Share of the snapshot's raw total, or 0.0 when the total is 0.
    share: float
    severity_counts: Mapping[str, int]


@dataclass(frozen=True)
class DebtChange:
    """What moved since the previous recorded calculation for the same scope."""

    previous_snapshot_id: str | None
    previous_total: float
    delta: float
    resolved_debt_ids: tuple[str, ...]
    introduced_debt_ids: tuple[str, ...]
    unchanged_count: int

    @property
    def has_previous(self) -> bool:
        return self.previous_snapshot_id is not None


@dataclass(frozen=True)
class EvidenceDebtSnapshot:
    """One case's debt, as computed over one reader's authorized scope.

    `scope_fingerprint` is load-bearing rather than incidental. Debt is computed
    over the evidence a particular reader may see, so two readers legitimately
    get different totals — and a snapshot is only comparable with another
    snapshot taken over the same scope. Trend and history are keyed on it, which
    is what stops a narrow reader from reading a cleared reader's numbers.
    """

    snapshot_id: str
    case_id: str
    calculated_at: str
    calculated_by: str
    correlation_id: str
    total_debt: float
    normalized_debt: float
    band: DebtBand
    item_count: int
    breakdown: tuple[EvidenceDebtBreakdown, ...]
    top_items: tuple[EvidenceDebtItem, ...]
    debt_ids: tuple[str, ...]
    evidence_in_scope: int
    excluded_evidence_count: int
    scope_fingerprint: str
    policy_version: str
    debt_engine_version: str
    persisted: bool = False

    def category(self, category: DebtCategory) -> EvidenceDebtBreakdown:
        for entry in self.breakdown:
            if entry.category is category:
                return entry
        raise KeyError(category)


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def debt_identity(
    case_id: str,
    category: DebtCategory,
    subject_type: DebtSubjectType,
    reference: str,
    *discriminators: str,
) -> str:
    """Stable identity for "this gap, about this subject, in this case".

    Deterministic and free of timestamps, run ids and ordering, so a
    recalculation over unchanged state recognises the item it already produced
    instead of manufacturing a new one.
    """
    return (
        "DEBT-"
        + _digest(
            case_id,
            category.value,
            subject_type.value,
            reference,
            *discriminators,
        )[:16].upper()
    )


def snapshot_identity(
    case_id: str, scope_fingerprint: str, calculated_at: str, policy_version: str
) -> str:
    return (
        "DSNAP-"
        + _digest(case_id, scope_fingerprint, calculated_at, policy_version)[:16].upper()
    )


def scope_fingerprint(evidence_ids: Iterable[str]) -> str:
    """Identity of the evidence scope a snapshot was computed over."""
    return _digest(*sorted(evidence_ids))[:16].upper()


def fact_fingerprint(
    category: DebtCategory,
    severity: DebtSeverity,
    reason: DebtReason,
    subject: DebtSubject,
    weighting: DebtWeighting,
    supporting_evidence_ids: Iterable[str],
    policy_version: str,
    engine_version: str,
) -> str:
    """What an item asserts, so an unchanged assertion is not rewritten.

    Deliberately excludes `calculated_at` and the item's status: recalculating
    an unchanged gap must be a no-op, and a person's acknowledgement is not part
    of what the detector found.
    """
    return _digest(
        category.value,
        severity.value,
        reason.value,
        subject.subject_type.value,
        subject.reference,
        ",".join(sorted(subject.entity_refs)),
        f"{weighting.weighted_contribution:.6f}",
        f"{weighting.affected_scope}",
        ",".join(sorted(supporting_evidence_ids)),
        policy_version,
        engine_version,
    )


def build_breakdown(items: Iterable[EvidenceDebtItem]) -> tuple[EvidenceDebtBreakdown, ...]:
    """Per-category totals for every category, in a stable order."""
    collected = list(items)
    total = sum(item.contribution for item in collected)
    breakdown: list[EvidenceDebtBreakdown] = []
    for category in DebtCategory:
        matching = [item for item in collected if item.category is category]
        contribution = sum(item.contribution for item in matching)
        severity_counts = {
            severity.value: sum(1 for item in matching if item.severity is severity)
            for severity in DebtSeverity
        }
        breakdown.append(
            EvidenceDebtBreakdown(
                category=category,
                item_count=len(matching),
                weighted_contribution=round(contribution, 6),
                share=round(contribution / total, 6) if total > 0 else 0.0,
                severity_counts=severity_counts,
            )
        )
    return tuple(breakdown)


@dataclass(frozen=True)
class DebtFinding:
    """What a detector produces, before weighting, identity and lifecycle.

    Detectors state facts; the service turns facts into an item. Keeping them
    apart is what makes the detectors pure functions of (view, policy) with no
    clock, no storage and no idea what a previous calculation concluded.
    """

    category: DebtCategory
    severity: DebtSeverity
    reason: DebtReason
    subject: DebtSubject
    explanation: Mapping[str, Any]
    supporting_evidence_ids: tuple[str, ...] = ()
    related_resolution_ids: tuple[str, ...] = ()
    related_finding_ids: tuple[str, ...] = ()
    #: How many distinct things in the case this gap touches. Feeds the scope
    #: factor; a detector knows it and the weighting policy maps it.
    affected_scope: int = 1
    #: Whether the case's recorded reasoning rests on the affected evidence.
    critical: bool = False
    #: Extra parts of this finding's identity, beyond category and subject — a
    #: conflict rule name, an expectation id.
    discriminators: tuple[str, ...] = ()
    blocking_reason: DebtBlocker = DebtBlocker.NONE
    metrics: Mapping[str, Any] = field(default_factory=dict)
