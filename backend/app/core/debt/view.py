"""The only investigation state the debt detectors are allowed to see.

This is the security boundary of the phase, and it is structural rather than
procedural. A detector never receives a repository, an object store, an
`EvidenceRecord` or a payload. It receives a `CaseDebtView` assembled from
already-authorized state, and that type carries no resource value at all — an
entity is the hashed `entity_ref` resolution already publishes, an attribute is
its name, a conflict is a rule name.

So restricted evidence cannot leak through a debt item by being forgotten in one
code path: there is no code path where a detector holds one. The scope question
— which evidence a reader may see — is settled before the view exists, and an
observation outside it never reaches this module. A conflict whose only reason
to exist is restricted evidence is not "one hidden conflict" in a narrow
reader's answer; it is not in their view, and it is not in their total.

Two derived rules the assembly enforces, both mirroring what the subsystems
that own the state already do:

- **a resolution is in scope only when *both* its evidence items are**, exactly
  as `EntityResolutionService` decides readability;
- **a signal is in scope only when *every* evidence item it cites is**, because
  a finding computed partly from evidence a reader cannot see would disclose
  that the evidence exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class DebtResultView:
    """One analysis result, reduced to what debt detection needs.

    `conflict_metrics` are counts an analyzer already reported — never a
    re-reading of the evidence payload. The debt engine must not become a second
    analyzer, and a count of disagreements carries no identifier.
    """

    result_id: str
    task_type: str
    state: str
    evidence_version_id: str
    created_at: str
    conflict_metrics: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class DebtEvidenceView:
    """One authorized evidence item: metadata and lifecycle state only."""

    evidence_id: str
    source_id: str
    classification: str
    state: str
    latest_version_id: str | None
    version_count: int
    results: tuple[DebtResultView, ...] = ()

    def current_result(self, task_type: str) -> DebtResultView | None:
        for result in self.results:
            if result.task_type == task_type and result.state == "CURRENT":
                return result
        return None

    def stale_results(self, task_type: str) -> tuple[DebtResultView, ...]:
        return tuple(
            result
            for result in self.results
            if result.task_type == task_type and result.state == "STALE"
        )

    @property
    def task_types(self) -> tuple[str, ...]:
        return tuple(sorted({result.task_type for result in self.results}))


@dataclass(frozen=True)
class DebtConflictView:
    """One recorded disagreement between two evidence items.

    Field names and a rule name, never the values that disagreed.
    """

    attribute: str
    rule: str
    penalty: float
    blocks_auto_accept: bool


@dataclass(frozen=True)
class DebtResolutionView:
    """One identity decision, as debt is allowed to see it."""

    resolution_id: str
    lineage_id: str
    status: str
    recommendation: str
    left_evidence_id: str
    right_evidence_id: str
    left_entity_ref: str
    right_entity_ref: str
    score: float
    evidence_weight: float
    conflicts: tuple[DebtConflictView, ...] = ()
    #: The review actions recorded against this decision, oldest first. A
    #: deferral is a look that reached no outcome, so the queue keeps the item.
    review_actions: tuple[str, ...] = ()

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(sorted({self.left_evidence_id, self.right_evidence_id}))

    @property
    def entity_refs(self) -> tuple[str, ...]:
        return tuple(sorted({self.left_entity_ref, self.right_entity_ref}))

    @property
    def asserts_same_entity(self) -> bool:
        return self.status in ("AUTO_ACCEPTED", "APPROVED")


@dataclass(frozen=True)
class DebtSignalView:
    """One recorded finding, and the evidence it says it rests on."""

    signal_id: str
    signal_type: str
    score: float
    reasons: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    entity_refs: tuple[str, ...]


@dataclass(frozen=True)
class CaseDebtView:
    """One case's investigation state, as one reader is authorized to see it."""

    case_id: str
    evidence: tuple[DebtEvidenceView, ...]
    resolutions: tuple[DebtResolutionView, ...]
    signals: tuple[DebtSignalView, ...]
    #: The authorized evidence scope this view was built from. A snapshot is
    #: only comparable with another taken over the same scope.
    evidence_ids: tuple[str, ...]
    excluded_evidence_count: int
    masked_fields: tuple[str, ...] = ()

    @property
    def source_ids(self) -> frozenset[str]:
        return frozenset(item.source_id for item in self.evidence)

    def evidence_item(self, evidence_id: str) -> DebtEvidenceView | None:
        for item in self.evidence:
            if item.evidence_id == evidence_id:
                return item
        return None

    def evidence_from(self, source_id: str) -> tuple[DebtEvidenceView, ...]:
        return tuple(item for item in self.evidence if item.source_id == source_id)

    def cited_evidence_ids(self) -> frozenset[str]:
        """Evidence the case's recorded reasoning actually rests on.

        A finding that names it, or an accepted identity link derived from it.
        This is what separates "low-trust evidence exists in the case" from
        "low-trust evidence is holding a conclusion up" — only the second is
        debt, and only this property can tell them apart.
        """
        cited: set[str] = set()
        for signal in self.signals:
            cited.update(signal.supporting_evidence_ids)
        for resolution in self.resolutions:
            if resolution.asserts_same_entity:
                cited.update(resolution.evidence_ids)
        return frozenset(cited)
