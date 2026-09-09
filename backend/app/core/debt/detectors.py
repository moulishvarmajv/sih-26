"""Deterministic debt detection.

Pure functions of (`CaseDebtView`, `EvidenceDebtPolicy`). No storage, no clock,
no randomness, and no knowledge of what a previous calculation concluded — so
the same investigation state and the same policy version always produce the same
findings, in the same order.

Each detector consumes state a subsystem already owns and publishes. Nothing
here re-derives an identity decision, re-runs an analysis or re-reads an
evidence payload: entity resolution stays authoritative for identity, the
evidence lifecycle for versions and results, analytics for findings. Debt only
observes what those systems say about themselves and names the gaps.

The ordering of the detectors is load-bearing in one place: finding support is
computed last, because "this finding rests on evidence that is itself in debt"
is a statement about the other detectors' output.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from app.core.debt.models import (
    DebtBlocker,
    DebtCategory,
    DebtFinding,
    DebtReason,
    DebtSeverity,
    DebtSubject,
    DebtSubjectType,
)
from app.core.debt.policy import EvidenceDebtPolicy, ExpectationKind
from app.core.debt.view import CaseDebtView, DebtSignalView

#: A deferral is a recorded look that reached no outcome. Resolution keeps the
#: decision open on purpose, so the debt item stays and only its reason changes.
_DEFER = "DEFER"


def detect(view: CaseDebtView, policy: EvidenceDebtPolicy) -> list[DebtFinding]:
    """Every gap the policy recognises in one authorized case view."""
    findings: list[DebtFinding] = []
    findings.extend(unresolved(view, policy))
    findings.extend(human_review(view, policy))
    findings.extend(conflicting(view, policy))
    findings.extend(weak(view, policy))
    findings.extend(missing(view, policy))
    findings.extend(stale(view, policy))
    findings.extend(unsupported_findings(view, policy, findings))
    return _ordered(findings, policy)


# -- A. unresolved identity ---------------------------------------------------


def unresolved(view: CaseDebtView, policy: EvidenceDebtPolicy) -> list[DebtFinding]:
    """Pairs the system compared and could not settle, and that nobody is asked about.

    A CANDIDATE decision scored below the review floor: the observations were
    compared, nothing was asserted, and the pair is not in a review queue. The
    debt is that the investigation does not know whether these are one entity —
    stated without asserting that they are.
    """
    cited = view.cited_evidence_ids()
    findings = []
    for resolution in view.resolutions:
        if resolution.status != "CANDIDATE":
            continue
        findings.append(
            DebtFinding(
                category=DebtCategory.UNRESOLVED,
                severity=policy.resolution.unresolved_severity,
                reason=DebtReason.RESOLUTION_BELOW_REVIEW_FLOOR,
                subject=DebtSubject(
                    subject_type=DebtSubjectType.RESOLUTION,
                    reference=resolution.lineage_id,
                    entity_refs=resolution.entity_refs,
                ),
                explanation={
                    "resolution_status": resolution.status,
                    "recommendation": resolution.recommendation,
                    "score": round(resolution.score, 4),
                    "evidence_weight": round(resolution.evidence_weight, 4),
                },
                supporting_evidence_ids=resolution.evidence_ids,
                related_resolution_ids=(resolution.resolution_id,),
                affected_scope=len(resolution.evidence_ids),
                critical=bool(set(resolution.evidence_ids) & cited),
                blocking_reason=DebtBlocker.AWAITING_ENTITY_RESOLUTION,
                metrics={"score": resolution.score},
            )
        )
    return findings


# -- F. outstanding human decision -------------------------------------------


def human_review(view: CaseDebtView, policy: EvidenceDebtPolicy) -> list[DebtFinding]:
    """Decisions waiting on a person.

    A REVIEW_REQUIRED resolution is exactly one debt item, never two: it is both
    an open identity question and an open piece of work, and counting it twice
    would inflate the case's debt for one gap. The category is the one that says
    what has to happen — a person has to look.

    A deferral is a recorded look that reached no outcome, so the item stays and
    the reason says why. Approve or reject and it disappears from this category
    on the next calculation.
    """
    cited = view.cited_evidence_ids()
    findings = []
    for resolution in view.resolutions:
        if resolution.status != "REVIEW_REQUIRED":
            continue
        deferred = _DEFER in resolution.review_actions
        findings.append(
            DebtFinding(
                category=DebtCategory.HUMAN_REVIEW,
                severity=(
                    policy.resolution.deferred_severity
                    if deferred
                    else policy.resolution.awaiting_review_severity
                ),
                reason=(
                    DebtReason.RESOLUTION_REVIEW_DEFERRED
                    if deferred
                    else DebtReason.RESOLUTION_AWAITING_REVIEW
                ),
                subject=DebtSubject(
                    subject_type=DebtSubjectType.RESOLUTION,
                    reference=resolution.lineage_id,
                    entity_refs=resolution.entity_refs,
                ),
                explanation={
                    "resolution_status": resolution.status,
                    "recommendation": resolution.recommendation,
                    "score": round(resolution.score, 4),
                    "review_count": len(resolution.review_actions),
                    "review_actions": list(resolution.review_actions),
                },
                supporting_evidence_ids=resolution.evidence_ids,
                related_resolution_ids=(resolution.resolution_id,),
                affected_scope=len(resolution.evidence_ids),
                critical=bool(set(resolution.evidence_ids) & cited),
                blocking_reason=DebtBlocker.AWAITING_HUMAN_REVIEW,
                metrics={"score": resolution.score},
            )
        )
    return findings


# -- B. conflicting evidence --------------------------------------------------


def conflicting(view: CaseDebtView, policy: EvidenceDebtPolicy) -> list[DebtFinding]:
    """Evidence that disagrees with other evidence on a material attribute.

    Two deterministic sources, both already computed elsewhere:

    - a resolution's recorded conflicts, which name the attribute, the rule and
      whether the disagreement was strong enough to block an automatic merge;
    - a metric an analyzer already reported as an internal disagreement — one
      handset observed under two subscriber identities within a single export.

    A rejected decision contributes nothing: a person concluded the two
    observations denote different entities, so the disagreement was the correct
    answer rather than an unexplained one.
    """
    cited = view.cited_evidence_ids()
    findings = _resolution_conflicts(view, policy, cited)
    findings.extend(_result_conflicts(view, policy, cited))
    return findings


def _resolution_conflicts(
    view: CaseDebtView, policy: EvidenceDebtPolicy, cited: frozenset[str]
) -> list[DebtFinding]:
    findings = []
    for resolution in view.resolutions:
        if resolution.status not in policy.resolution.conflict_statuses:
            continue
        for conflict in resolution.conflicts:
            findings.append(
                DebtFinding(
                    category=DebtCategory.CONFLICTING,
                    severity=(
                        policy.resolution.blocking_conflict_severity
                        if conflict.blocks_auto_accept
                        else policy.resolution.conflict_severity
                    ),
                    reason=(
                        DebtReason.RESOLUTION_CONFLICT_BLOCKS_ACCEPTANCE
                        if conflict.blocks_auto_accept
                        else DebtReason.RESOLUTION_ATTRIBUTE_CONFLICT
                    ),
                    subject=DebtSubject(
                        subject_type=DebtSubjectType.RESOLUTION,
                        reference=resolution.lineage_id,
                        entity_refs=resolution.entity_refs,
                    ),
                    explanation={
                        "conflict_rule": conflict.rule,
                        "conflict_attribute": conflict.attribute,
                        "blocks_auto_accept": conflict.blocks_auto_accept,
                        "penalty": round(conflict.penalty, 4),
                        "resolution_status": resolution.status,
                        "participating_evidence_ids": list(resolution.evidence_ids),
                    },
                    supporting_evidence_ids=resolution.evidence_ids,
                    related_resolution_ids=(resolution.resolution_id,),
                    affected_scope=len(resolution.evidence_ids),
                    critical=bool(set(resolution.evidence_ids) & cited),
                    discriminators=(conflict.rule,),
                    blocking_reason=DebtBlocker.AWAITING_HUMAN_REVIEW,
                    metrics={"penalty": conflict.penalty},
                )
            )
    return findings


def _result_conflicts(
    view: CaseDebtView, policy: EvidenceDebtPolicy, cited: frozenset[str]
) -> list[DebtFinding]:
    findings = []
    for evidence in view.evidence:
        for rule in policy.result_conflicts:
            result = evidence.current_result(rule.task_type)
            if result is None:
                continue
            count = int(result.conflict_metrics.get(rule.metric, 0) or 0)
            if count <= 0:
                continue
            findings.append(
                DebtFinding(
                    category=DebtCategory.CONFLICTING,
                    severity=rule.severity,
                    reason=DebtReason.OBSERVATIONS_DISAGREE_WITHIN_EVIDENCE,
                    subject=DebtSubject(
                        subject_type=DebtSubjectType.EVIDENCE,
                        reference=evidence.evidence_id,
                    ),
                    explanation={
                        "conflict_rule": rule.rule,
                        "conflict_metric": rule.metric,
                        "conflict_count": count,
                        "task_type": rule.task_type,
                        "result_id": result.result_id,
                        "evidence_version_id": result.evidence_version_id,
                    },
                    supporting_evidence_ids=(evidence.evidence_id,),
                    affected_scope=count,
                    critical=evidence.evidence_id in cited,
                    discriminators=(rule.rule,),
                    blocking_reason=DebtBlocker.AWAITING_HUMAN_REVIEW,
                    metrics={"conflict_count": count},
                )
            )
    return findings


# -- C. weak / low-trust support ---------------------------------------------


def weak(view: CaseDebtView, policy: EvidenceDebtPolicy) -> list[DebtFinding]:
    """Reasoning resting on evidence below the policy's trust floor.

    An INFERRED fact is not automatically bad evidence — a great deal of useful
    investigative material is inferred, and flagging all of it would make the
    metric noise. It becomes debt when the case's recorded reasoning rests on
    it: a finding names it, or an accepted identity link was derived from it.
    Low-trust evidence nothing depends on is simply low-trust evidence.
    """
    cited = view.cited_evidence_ids()
    findings = []
    for evidence in view.evidence:
        if evidence.classification not in policy.weak.trust_floor:
            continue
        supports = evidence.evidence_id in cited
        if policy.weak.requires_material_support and not supports:
            continue
        findings.append(
            DebtFinding(
                category=DebtCategory.WEAK,
                severity=policy.weak.severity_by_classification[evidence.classification],
                reason=DebtReason.SUPPORTING_EVIDENCE_BELOW_TRUST_FLOOR,
                subject=DebtSubject(
                    subject_type=DebtSubjectType.EVIDENCE,
                    reference=evidence.evidence_id,
                ),
                explanation={
                    "classification": evidence.classification,
                    "trust_floor": sorted(policy.weak.trust_floor),
                    "materially_supports_reasoning": supports,
                    "source_id": evidence.source_id,
                },
                supporting_evidence_ids=(evidence.evidence_id,),
                affected_scope=len(_dependents(view, evidence.evidence_id)),
                critical=supports,
                blocking_reason=DebtBlocker.AWAITING_ADDITIONAL_EVIDENCE,
            )
        )
    return findings


# -- D. missing expected evidence --------------------------------------------


def missing(view: CaseDebtView, policy: EvidenceDebtPolicy) -> list[DebtFinding]:
    """Corroboration the policy expects for this case and that is not there.

    Nothing is invented: an expectation exists only because a deployment wrote
    it into the policy, and it fires only when its trigger source is actually
    present in the case. A case with no CDR evidence is not missing a subscriber
    register.
    """
    cited = view.cited_evidence_ids()
    findings = []
    for expectation in policy.expectations:
        triggering = view.evidence_from(expectation.when_source_present)
        if not triggering:
            continue

        if expectation.kind is ExpectationKind.SOURCE_PRESENT:
            if view.evidence_from(str(expectation.expected_source_id)):
                continue
            findings.append(
                DebtFinding(
                    category=DebtCategory.MISSING,
                    severity=expectation.severity,
                    reason=DebtReason.EXPECTED_SOURCE_ABSENT,
                    subject=DebtSubject(
                        subject_type=DebtSubjectType.EXPECTATION,
                        reference=expectation.expectation_id,
                    ),
                    explanation={
                        "expectation_id": expectation.expectation_id,
                        "expectation_kind": expectation.kind.value,
                        "expected_source_id": expectation.expected_source_id,
                        "triggered_by_source_id": expectation.when_source_present,
                        "triggering_evidence_count": len(triggering),
                    },
                    supporting_evidence_ids=tuple(
                        sorted(item.evidence_id for item in triggering)
                    ),
                    affected_scope=len(triggering),
                    critical=bool(
                        {item.evidence_id for item in triggering} & cited
                    ),
                    blocking_reason=DebtBlocker.AWAITING_ADDITIONAL_EVIDENCE,
                )
            )
            continue

        task_type = str(expectation.expected_task_type)
        for evidence in triggering:
            if evidence.current_result(task_type) is not None:
                continue
            if evidence.stale_results(task_type):
                # The analysis is not missing, it is out of date, and the stale
                # detector says so. Reporting one gap under two categories would
                # inflate the total for a single thing to fix.
                continue
            findings.append(
                DebtFinding(
                    category=DebtCategory.MISSING,
                    severity=expectation.severity,
                    reason=DebtReason.EXPECTED_ANALYSIS_ABSENT,
                    subject=DebtSubject(
                        subject_type=DebtSubjectType.EVIDENCE,
                        reference=evidence.evidence_id,
                    ),
                    explanation={
                        "expectation_id": expectation.expectation_id,
                        "expectation_kind": expectation.kind.value,
                        "expected_task_type": task_type,
                        "source_id": evidence.source_id,
                        "recorded_task_types": list(evidence.task_types),
                    },
                    supporting_evidence_ids=(evidence.evidence_id,),
                    affected_scope=1,
                    critical=evidence.evidence_id in cited,
                    discriminators=(expectation.expectation_id,),
                    blocking_reason=DebtBlocker.AWAITING_REANALYSIS,
                )
            )
    return findings


# -- E. stale analysis --------------------------------------------------------


def stale(view: CaseDebtView, policy: EvidenceDebtPolicy) -> list[DebtFinding]:
    """Results computed from a version that no longer stands.

    The evidence lifecycle already owns this transition: a new version marks the
    results computed from the previous one STALE. Debt adds nothing to that
    judgement — it reports where a stale result has not been replaced by a
    current one for the evidence's latest version, which is precisely where
    dependent reasoning is out of date.

    Only the relationships the lifecycle already records are used. There is no
    transitive dependency graph in this phase, so a result derived from *other*
    evidence is not chased.
    """
    cited = view.cited_evidence_ids()
    findings = []
    for evidence in view.evidence:
        for task_type in evidence.task_types:
            stale_results = evidence.stale_results(task_type)
            if not stale_results:
                continue
            current = evidence.current_result(task_type)
            if current is not None and current.evidence_version_id == evidence.latest_version_id:
                continue  # recomputed against the version that stands
            findings.append(
                DebtFinding(
                    category=DebtCategory.STALE,
                    severity=policy.stale_severity,
                    reason=DebtReason.RESULT_COMPUTED_FROM_SUPERSEDED_VERSION,
                    subject=DebtSubject(
                        subject_type=DebtSubjectType.EVIDENCE,
                        reference=evidence.evidence_id,
                    ),
                    explanation={
                        "task_type": task_type,
                        "stale_result_ids": [result.result_id for result in stale_results],
                        "stale_version_ids": sorted(
                            {result.evidence_version_id for result in stale_results}
                        ),
                        "latest_version_id": evidence.latest_version_id,
                        "current_result_id": None if current is None else current.result_id,
                        "version_count": evidence.version_count,
                    },
                    supporting_evidence_ids=(evidence.evidence_id,),
                    affected_scope=len(stale_results),
                    critical=evidence.evidence_id in cited,
                    discriminators=(task_type,),
                    blocking_reason=DebtBlocker.AWAITING_REANALYSIS,
                )
            )
    return findings


# -- G. finding support -------------------------------------------------------


def unsupported_findings(
    view: CaseDebtView,
    policy: EvidenceDebtPolicy,
    prior: Sequence[DebtFinding],
) -> list[DebtFinding]:
    """Recorded findings whose support is incomplete or itself in debt.

    Composed from the other detectors rather than re-deriving anything: if a
    signal's supporting evidence carries unresolved, conflicting, weak or stale
    debt, the finding inherits a dependency on it. A finding resting on
    observed, analysed, unconflicted evidence produces nothing at all, which is
    what makes the category meaningful.
    """
    support = policy.finding_support
    by_evidence = _debt_by_evidence(prior, support.dependency_categories)
    findings = []
    for signal in view.signals:
        if not signal.supporting_evidence_ids:
            findings.append(
                _finding_debt(
                    signal,
                    support.no_support_severity,
                    DebtReason.FINDING_HAS_NO_SUPPORTING_EVIDENCE,
                    {"supporting_evidence_count": 0},
                    (),
                    affected_scope=1,
                )
            )
            continue

        for category in sorted(
            {
                found.category
                for evidence_id in signal.supporting_evidence_ids
                for found in by_evidence.get(evidence_id, ())
            },
            key=lambda item: item.value,
        ):
            affected = tuple(
                sorted(
                    evidence_id
                    for evidence_id in signal.supporting_evidence_ids
                    if any(
                        found.category is category
                        for found in by_evidence.get(evidence_id, ())
                    )
                )
            )
            findings.append(
                _finding_debt(
                    signal,
                    support.dependency_severity,
                    _DEPENDENCY_REASONS[category],
                    {
                        "dependency_category": category.value,
                        "supporting_evidence_count": len(signal.supporting_evidence_ids),
                        "affected_evidence_ids": list(affected),
                    },
                    affected,
                    affected_scope=len(affected),
                )
            )

        thin = sorted(set(signal.reasons) & support.weak_relationship_reasons)
        if thin:
            findings.append(
                _finding_debt(
                    signal,
                    support.weak_relationship_severity,
                    DebtReason.FINDING_RESTS_ON_SINGLE_WEAK_RELATIONSHIP,
                    {"signal_reasons": thin},
                    signal.supporting_evidence_ids,
                    affected_scope=1,
                )
            )
    return findings


_DEPENDENCY_REASONS: Mapping[DebtCategory, DebtReason] = {
    DebtCategory.UNRESOLVED: DebtReason.FINDING_DEPENDS_ON_UNRESOLVED_ENTITY,
    DebtCategory.HUMAN_REVIEW: DebtReason.FINDING_DEPENDS_ON_UNRESOLVED_ENTITY,
    DebtCategory.CONFLICTING: DebtReason.FINDING_DEPENDS_ON_CONFLICTING_EVIDENCE,
    DebtCategory.WEAK: DebtReason.FINDING_DEPENDS_ON_WEAK_EVIDENCE,
    DebtCategory.STALE: DebtReason.FINDING_DEPENDS_ON_STALE_ANALYSIS,
}


def _finding_debt(
    signal: DebtSignalView,
    severity: DebtSeverity,
    reason: DebtReason,
    explanation: Mapping[str, Any],
    affected_evidence: Iterable[str],
    affected_scope: int,
) -> DebtFinding:
    return DebtFinding(
        category=DebtCategory.UNSUPPORTED_FINDING,
        severity=severity,
        reason=reason,
        subject=DebtSubject(
            subject_type=DebtSubjectType.SIGNAL,
            reference=signal.signal_id,
            entity_refs=signal.entity_refs,
        ),
        explanation={
            "signal_type": signal.signal_type,
            "signal_score": round(signal.score, 4),
            **dict(explanation),
        },
        supporting_evidence_ids=tuple(sorted(set(affected_evidence))),
        related_finding_ids=(signal.signal_id,),
        affected_scope=max(1, affected_scope),
        # A finding *is* the case's reasoning, so debt on its support always
        # counts as resting on something the investigation relies upon.
        critical=True,
        discriminators=(reason.value,),
        blocking_reason=DebtBlocker.AWAITING_ADDITIONAL_EVIDENCE,
    )


# -- helpers ------------------------------------------------------------------


def _debt_by_evidence(
    findings: Sequence[DebtFinding], categories: frozenset[DebtCategory]
) -> dict[str, list[DebtFinding]]:
    index: dict[str, list[DebtFinding]] = {}
    for finding in findings:
        if finding.category not in categories:
            continue
        for evidence_id in finding.supporting_evidence_ids:
            index.setdefault(evidence_id, []).append(finding)
    return index


def _dependents(view: CaseDebtView, evidence_id: str) -> set[str]:
    """What in the case would move if this evidence changed.

    Findings that cite it and identity links derived from it — the same
    relationships the other detectors use, counted so the weighting can tell a
    gap that touches one thing from one that touches the whole case.
    """
    dependents = {evidence_id}
    for signal in view.signals:
        if evidence_id in signal.supporting_evidence_ids:
            dependents.add(signal.signal_id)
    for resolution in view.resolutions:
        if evidence_id in resolution.evidence_ids:
            dependents.add(resolution.lineage_id)
    return dependents


def _ordered(
    findings: Sequence[DebtFinding], policy: EvidenceDebtPolicy
) -> list[DebtFinding]:
    """A stable order, and the policy's per-category cap applied within it.

    Sorted by facts only — never by score — so two runs over identical state
    produce identical lists, and a cap truncates the same tail both times.
    """
    ordered = sorted(
        findings,
        key=lambda finding: (
            finding.category.value,
            finding.subject.subject_type.value,
            finding.subject.reference,
            finding.reason.value,
            finding.discriminators,
        ),
    )
    counts: dict[DebtCategory, int] = {}
    capped: list[DebtFinding] = []
    for finding in ordered:
        seen = counts.get(finding.category, 0)
        if seen >= policy.limits.max_items_per_category:
            continue
        counts[finding.category] = seen + 1
        capped.append(finding)
    return capped
