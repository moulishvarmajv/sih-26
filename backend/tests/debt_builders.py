"""Builders for hand-made `CaseDebtView`s.

The detectors are pure functions of (view, policy), so the sharpest tests give
them a view built by hand: exactly one thing wrong, nothing else, and the answer
known before the code runs. Everything the builders default to is the *absence*
of a gap — observed evidence, a current result, a settled decision — so a test
adds only the fact it is about.
"""
from __future__ import annotations

from app.core.debt.view import (
    CaseDebtView,
    DebtConflictView,
    DebtEvidenceView,
    DebtResolutionView,
    DebtResultView,
    DebtSignalView,
)

CASE = "CASE-DEBT"
CDR = "SYNTHETIC_CDR"
REGISTER = "SYNTHETIC_SUBSCRIBER_REGISTER"
SUMMARY = "CDR_SUMMARY"


def result(
    result_id: str = "RES-1",
    task_type: str = SUMMARY,
    state: str = "CURRENT",
    version_id: str = "EV-1-v1",
    conflict_metrics: dict[str, int] | None = None,
) -> DebtResultView:
    return DebtResultView(
        result_id=result_id,
        task_type=task_type,
        state=state,
        evidence_version_id=version_id,
        created_at="2026-03-01T00:00:00+00:00",
        conflict_metrics=conflict_metrics or {},
    )


def evidence(
    evidence_id: str = "EV-1",
    source_id: str = CDR,
    classification: str = "OBSERVED",
    latest_version_id: str | None = None,
    version_count: int = 1,
    results: tuple[DebtResultView, ...] = (),
) -> DebtEvidenceView:
    return DebtEvidenceView(
        evidence_id=evidence_id,
        source_id=source_id,
        classification=classification,
        state="AVAILABLE",
        latest_version_id=latest_version_id or f"{evidence_id}-v{version_count}",
        version_count=version_count,
        results=results,
    )


def analysed(evidence_id: str = "EV-1", source_id: str = CDR, **kwargs) -> DebtEvidenceView:
    """Evidence with a current result, so the analysis expectation is satisfied."""
    return evidence(
        evidence_id,
        source_id,
        results=(result(f"RES-{evidence_id}", version_id=f"{evidence_id}-v1"),),
        **kwargs,
    )


def conflict(
    rule: str = "DIFFERENT_NATIONAL_ID_REFERENCE",
    attribute: str = "national_id_ref",
    penalty: float = 0.4,
    blocks: bool = True,
) -> DebtConflictView:
    return DebtConflictView(
        attribute=attribute, rule=rule, penalty=penalty, blocks_auto_accept=blocks
    )


def resolution(
    lineage_id: str = "ERL-1",
    status: str = "APPROVED",
    recommendation: str = "MATCH",
    left_evidence_id: str = "EV-1",
    right_evidence_id: str = "EV-2",
    score: float = 0.9,
    conflicts: tuple[DebtConflictView, ...] = (),
    review_actions: tuple[str, ...] = (),
) -> DebtResolutionView:
    return DebtResolutionView(
        resolution_id=f"ER-{lineage_id[4:]}-v1",
        lineage_id=lineage_id,
        status=status,
        recommendation=recommendation,
        left_evidence_id=left_evidence_id,
        right_evidence_id=right_evidence_id,
        left_entity_ref="person:aaaa1111",
        right_entity_ref="person:bbbb2222",
        score=score,
        evidence_weight=0.7,
        conflicts=conflicts,
        review_actions=review_actions,
    )


def signal(
    signal_id: str = "SIG-1",
    supporting_evidence_ids: tuple[str, ...] = ("EV-1",),
    signal_type: str = "HIGH_CONNECTIVITY",
    reasons: tuple[str, ...] = ("DEGREE_ABOVE_THRESHOLD",),
    score: float = 0.5,
) -> DebtSignalView:
    return DebtSignalView(
        signal_id=signal_id,
        signal_type=signal_type,
        score=score,
        reasons=reasons,
        supporting_evidence_ids=supporting_evidence_ids,
        entity_refs=("phone:cccc3333",),
    )


def view(
    evidence_items: tuple[DebtEvidenceView, ...] = (),
    resolutions: tuple[DebtResolutionView, ...] = (),
    signals: tuple[DebtSignalView, ...] = (),
    excluded: int = 0,
    case_id: str = CASE,
) -> CaseDebtView:
    return CaseDebtView(
        case_id=case_id,
        evidence=evidence_items,
        resolutions=resolutions,
        signals=signals,
        evidence_ids=tuple(sorted(item.evidence_id for item in evidence_items)),
        excluded_evidence_count=excluded,
    )
