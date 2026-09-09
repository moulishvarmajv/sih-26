"""Builds CASE-004, the case the evidence-debt suites reason about.

The shipped datasets carry the shape; this puts them through the real pipeline
so the debt engine reads what the other subsystems actually recorded rather than
a fixture's idea of it:

    ingest -> project to the graph -> analyse -> resolve -> record signals
           -> ingest a correction, which leaves one result stale

What CASE-004 contains, and which category each part exercises:

| part                                              | category            |
|---------------------------------------------------|---------------------|
| two register entries scoring alike on one number   | HUMAN_REVIEW        |
| register pairs sharing only a surname and a city   | UNRESOLVED          |
| entries agreeing on everything but an identity ref | CONFLICTING         |
| one handset recorded under two subscriber ids      | CONFLICTING         |
| an operator export declared INFERRED, and relied on| WEAK                |
| no device registry, and one export never analysed  | MISSING             |
| a corrected export whose result nobody recomputed  | STALE               |
| findings resting on any of the above               | UNSUPPORTED_FINDING |
| `CDR-EXPORT-DEBT-CLEAN`, which is simply fine      | none                |
| `REG-EXPORT-DEBT-RESTRICTED` at L3                 | the redaction test  |

The restricted register is the point of the last row: its single entry is the
only reason one identity conflict exists, so a reader without L3 must find no
trace of that conflict in any total, count, category, id, explanation or trend.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from app.core.domain.case import Case
from app.core.evidence.analysis import CDR_SUMMARY
from app.infrastructure.sources.synthetic_cdr import DEFAULT_DATASET, SyntheticCDRSource
from app.infrastructure.sources.synthetic_subscriber import SyntheticSubscriberRegisterSource

CASE = Case(
    id="CASE-004",
    agency_id="POLICE",
    title="Evidence debt case",
    status="OPEN",
    security_level="L1",
)
OTHER_CASE = Case(
    id="CASE-001",
    agency_id="POLICE",
    title="Other case",
    status="OPEN",
    security_level="L1",
)

MAIN_EXPORT = "CDR-EXPORT-DEBT-001"
RECON_EXPORT = "CDR-EXPORT-DEBT-RECON"
EXTRA_EXPORT = "CDR-EXPORT-DEBT-EXTRA"
CLEAN_EXPORT = "CDR-EXPORT-DEBT-CLEAN"
OPEN_REGISTER = "REG-EXPORT-DEBT-001"
RESTRICTED_REGISTER = "REG-EXPORT-DEBT-RESTRICTED"

#: Analysed during setup. `RECON_EXPORT` is deliberately left alone so the
#: missing-analysis expectation has something real to report.
ANALYSED = (MAIN_EXPORT, EXTRA_EXPORT, CLEAN_EXPORT)

#: Values only the restricted register carries, and identifiers the L2 privacy
#: policy masks. None of them may appear anywhere in an L2 reader's answer.
RESTRICTED_VALUES = (
    "NID-SYNTH-9Z",
    "REG-4090",
    "919840500001",
    "+91 98405 00001",
    "359881034512345",
    "Kavya Menon",
)


@dataclass
class DebtCaseFixture:
    """What a test needs to talk about the case it was just handed."""

    evidence_ids: dict[str, str]  # source record id -> evidence id
    restricted_evidence_id: str
    weak_evidence_id: str
    stale_evidence_id: str
    clean_evidence_id: str

    def id_of(self, source_record_id: str) -> str:
        return self.evidence_ids[source_record_id]


def build_debt_case(
    *,
    evidence_service,
    graph_service,
    resolution_service,
    analytics_service,
    evidence_repository,
    user,
    context,
    tmp_path: Path,
    case: Case = CASE,
) -> DebtCaseFixture:
    """Run the whole pipeline over CASE-004 as a fully cleared reader would.

    Setup is done at L3 on purpose: the interesting question is what a *narrower*
    reader sees afterwards, and that is only meaningful if everything was
    recorded in the first place.
    """
    evidence_service.ingest_from_source(case, SyntheticCDRSource())
    evidence_service.ingest_from_source(case, SyntheticSubscriberRegisterSource())
    graph_service.ingest_case_evidence(case)

    by_record = {
        record.source_record_id: record.id
        for record in evidence_repository.list_evidence_for_case(case.id)
    }
    for export in ANALYSED:
        evidence_service.analyze_evidence(user, context, case, by_record[export], CDR_SUMMARY)

    resolution_service.run(user, context, case)
    analytics_service.run(user, context, case)

    supersede_extra_export(evidence_service, case, tmp_path)

    return DebtCaseFixture(
        evidence_ids=by_record,
        restricted_evidence_id=by_record[RESTRICTED_REGISTER],
        weak_evidence_id=by_record[RECON_EXPORT],
        stale_evidence_id=by_record[EXTRA_EXPORT],
        clean_evidence_id=by_record[CLEAN_EXPORT],
    )


class ReplaySource:
    """Replays one record from a shipped dataset under a different case id.

    The datasets are keyed to `CASE-004`; the live suites write under a case id
    unique to the run so they can clean up exactly what they wrote. Fetching by
    the dataset's id and ingesting under the run's is what lets both use the
    same fixture data.
    """

    def __init__(self, source_id: str, item) -> None:
        self.source_id = source_id
        self._item = item

    def fetch(self, case_id: str):
        return [self._item]


def supersede_extra_export(evidence_service, case: Case, tmp_path: Path) -> None:
    """Ingest a corrected `CDR-EXPORT-DEBT-EXTRA`, leaving its result stale.

    A static dataset cannot hold two versions of one export, so the correction
    is made here — which is also what happens in practice when an operator
    re-sends an export with a duration fixed.

    The corrected export is fetched under the *dataset's* case id and ingested
    under the caller's, so this works whether the case is `CASE-004` or a live
    suite's per-run id. Fetching under the caller's id instead would silently
    return nothing for a live run, and the staleness it exists to create would
    never happen.
    """
    dataset = json.loads(DEFAULT_DATASET.read_text(encoding="utf-8"))
    for export in dataset["exports"]:
        if export["export_id"] == EXTRA_EXPORT:
            export["records"][0]["duration_seconds"] = 71
    corrected = tmp_path / "corrected_cdr.json"
    corrected.write_text(json.dumps(dataset), encoding="utf-8")

    source = SyntheticCDRSource(corrected)
    replayed = [
        item for item in source.fetch(CASE.id) if item.source_record_id == EXTRA_EXPORT
    ]
    assert replayed, f"the dataset no longer carries {EXTRA_EXPORT} for {CASE.id}"
    for item in replayed:
        evidence_service.ingest_from_source(case, ReplaySource(source.source_id, item))
