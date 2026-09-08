"""Evidence lifecycle: persistence, versioning, and VIEW/ANALYZE/REANALYZE semantics."""
import json

import pytest

from app.core.audit.event_store import FlightRecorderEvent
from app.core.evidence.analysis import CDR_SUMMARY, AnalyzerError, CdrSummaryAnalyzer
from app.core.evidence.models import ResultState, RunStatus, TrustClassification, VersionState
from app.core.evidence.service import (
    EvidenceAccessDenied,
    EvidenceNotFound,
    EvidenceService,
    canonical_bytes,
    evidence_id_for,
    sha256_hex,
)
from app.core.evidence.source import EvidenceSourceError, SourceEvidence
from app.infrastructure.local_object_store import LocalFileEvidenceObjectStore
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource, normalise_record
from app.infrastructure.sqlite_evidence_repository import SQLiteEvidenceRepository
from app.security.authorization.policy_engine import ClearanceAuthorizationEngine
from app.security.service import SecurityService
from tests.conftest import POLICE, make_case, make_context, make_user

CASE = make_case(case_id="CASE-001", security_level="L1")


@pytest.fixture
def repository(tmp_path):
    repo = SQLiteEvidenceRepository(tmp_path / "investigation.db")
    yield repo
    repo.close()


@pytest.fixture
def objects(tmp_path):
    return LocalFileEvidenceObjectStore(tmp_path / "objects")


@pytest.fixture
def security(engine, grants, event_store, policy):
    return SecurityService(
        engine=engine, grants=grants, event_store=event_store, clearance_policy=policy.clearance
    )


@pytest.fixture
def service(repository, objects, security, event_store, policy):
    return EvidenceService(
        repository=repository,
        object_store=objects,
        security=security,
        event_store=event_store,
        privacy=policy.privacy,
        analyzers=(CdrSummaryAnalyzer(),),
    )


@pytest.fixture
def investigator(grants):
    """L3 so nothing is masked by default; masking gets its own tests."""
    user = make_user(level="L3")
    grants.grant_agency(user.id, POLICE.id)
    grants.grant_case(user.id, POLICE.id, CASE.id, need_to_know=True)
    return user


@pytest.fixture
def context():
    return make_context(level="L3")


@pytest.fixture
def ingested(service, investigator):
    service.ingest_from_source(CASE, SyntheticCDRSource())
    return evidence_id_for(CASE.id, SyntheticCDRSource.source_id, "CDR-EXPORT-001")


def reingest(service, records):
    """Re-run ingestion with a modified payload to produce a new version."""

    class _Source:
        source_id = SyntheticCDRSource.source_id

        def fetch(self, case_id):
            return [
                SourceEvidence(
                    source_record_id="CDR-EXPORT-001",
                    payload={"export_id": "CDR-EXPORT-001", "records": records},
                    classification=TrustClassification.OBSERVED,
                    source_reference="TEST:CDR-EXPORT-001",
                    security_level="L2",
                    sensitive_fields=("caller", "callee", "imei", "imsi"),
                )
            ]

    return service.ingest_from_source(CASE, _Source())


# -- adapter ---------------------------------------------------------------


def test_synthetic_source_emits_observed_evidence():
    items = list(SyntheticCDRSource().fetch("CASE-001"))

    assert len(items) == 2
    first = items[0]
    assert first.source_record_id == "CDR-EXPORT-001"
    assert first.classification is TrustClassification.OBSERVED
    assert first.payload["record_count"] == 5
    assert "caller" in first.sensitive_fields


def test_source_preserves_messy_records_verbatim():
    """Duplicates and inconsistent formatting are observations, not defects to fix."""
    records = list(SyntheticCDRSource().fetch("CASE-001"))[0].payload["records"]

    assert records[0] == records[1]  # duplicate preserved
    assert records[2]["caller"] == "919876543210"  # formatting not rewritten
    assert "cell_id" not in records[4]  # missing optional field not invented
    imsis = {r["imsi"] for r in records if r["imei"] == "356938035643809"}
    assert len(imsis) == 2  # one IMEI, two IMSIs, kept as observed


def test_source_is_deterministic():
    first = list(SyntheticCDRSource().fetch("CASE-001"))
    second = list(SyntheticCDRSource().fetch("CASE-001"))

    assert [item.payload for item in first] == [item.payload for item in second]
    assert sha256_hex(canonical_bytes(first[0].payload)) == sha256_hex(
        canonical_bytes(second[0].payload)
    )


@pytest.mark.parametrize(
    "record",
    [
        {"caller": "+91", "timestamp": "t", "imei": "1", "imsi": "2", "duration_seconds": 1},
        {
            "caller": "+91",
            "callee": "+92",
            "timestamp": "t",
            "imei": "1",
            "imsi": "2",
            "duration_seconds": -5,
        },
        {
            "caller": "",
            "callee": "+92",
            "timestamp": "t",
            "imei": "1",
            "imsi": "2",
            "duration_seconds": 1,
        },
        "not-an-object",
    ],
)
def test_malformed_cdr_records_are_rejected(record):
    with pytest.raises(EvidenceSourceError):
        normalise_record(record, "CDR-EXPORT-001", 0)


def test_missing_dataset_is_rejected(tmp_path):
    with pytest.raises(EvidenceSourceError):
        list(SyntheticCDRSource(tmp_path / "absent.json").fetch("CASE-001"))


# -- persistence and versioning -------------------------------------------


def test_ingestion_creates_evidence_and_a_first_version(service, repository, ingested):
    evidence = repository.get_evidence(ingested)
    versions = repository.list_versions(ingested)

    assert evidence.case_id == CASE.id
    assert evidence.classification is TrustClassification.OBSERVED
    assert len(versions) == 1
    assert versions[0].version_number == 1
    assert versions[0].state is VersionState.CURRENT


def test_evidence_ids_are_deterministic():
    first = evidence_id_for("CASE-001", "SYNTHETIC_CDR", "CDR-EXPORT-001")
    second = evidence_id_for("CASE-001", "SYNTHETIC_CDR", "CDR-EXPORT-001")

    assert first == second
    assert first != evidence_id_for("CASE-002", "SYNTHETIC_CDR", "CDR-EXPORT-001")


def test_content_hash_is_deterministic(service, repository, objects, ingested):
    version = repository.get_latest_version(ingested)
    stored = json.loads(objects.get(version.payload_ref))

    assert len(version.content_hash) == 64
    assert sha256_hex(objects.get(version.payload_ref)) == version.content_hash
    assert sha256_hex(canonical_bytes(stored)) == version.content_hash
    # Key order must not change the digest.
    assert sha256_hex(canonical_bytes({"a": 1, "b": 2})) == sha256_hex(
        canonical_bytes({"b": 2, "a": 1})
    )


def test_list_evidence_for_case(service, repository, investigator, context, ingested):
    records = service.list_case_evidence(investigator, context, CASE)

    assert {record.id for record in records} == {
        evidence_id_for(CASE.id, "SYNTHETIC_CDR", "CDR-EXPORT-001"),
        evidence_id_for(CASE.id, "SYNTHETIC_CDR", "CDR-EXPORT-002"),
    }


def test_reingesting_unchanged_content_creates_no_new_version(service, repository, ingested):
    service.ingest_from_source(CASE, SyntheticCDRSource())

    assert len(repository.list_versions(ingested)) == 1


def test_changed_content_creates_a_second_version(service, repository, ingested):
    reingest(service, [{"caller": "+911111111111", "callee": "+912222222222"}])

    versions = repository.list_versions(ingested)
    assert [v.version_number for v in versions] == [1, 2]
    assert versions[0].state is VersionState.SUPERSEDED
    assert versions[1].state is VersionState.CURRENT
    assert repository.get_latest_version(ingested).version_number == 2


def test_older_version_remains_retrievable(service, repository, investigator, context, ingested):
    original = repository.get_latest_version(ingested)
    reingest(service, [{"caller": "+911111111111", "callee": "+912222222222"}])

    view = service.view_evidence(investigator, context, CASE, ingested, original.version_id)

    assert view.version.version_id == original.version_id
    assert view.version.version_number == 1
    assert view.payload["record_count"] == 5


# -- runs and results ------------------------------------------------------


def test_analyze_creates_a_run_recording_the_analysed_version(
    service, repository, investigator, context, ingested
):
    view = service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)

    run = repository.get_run(view.result.run_id)
    version = repository.get_latest_version(ingested)
    assert run.evidence_version_id == version.version_id
    assert run.input_hash == version.content_hash
    assert run.status is RunStatus.COMPLETED
    assert run.workflow_version == "1.0.0"
    assert run.rule_version == "cdr-summary-1.0.0"
    assert view.reused is False


def test_successful_result_is_current_and_derived(
    service, repository, investigator, context, ingested
):
    view = service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)

    assert view.result.state is ResultState.CURRENT
    assert view.result.classification is TrustClassification.DERIVED
    assert repository.get_current_result(ingested, CDR_SUMMARY).result_id == view.result.result_id
    assert view.payload["record_count"] == 5
    assert view.payload["duplicate_record_count"] == 1
    assert view.payload["imei_with_multiple_imsi_count"] == 1


def test_failed_run_never_produces_a_current_result(
    repository, objects, security, event_store, policy, investigator, context, ingested, service
):
    class _Failing:
        task_type = "BROKEN"
        workflow_version = "0.0.1"
        rule_version = "broken-0.0.1"

        def analyze(self, payload):
            raise AnalyzerError("cannot analyse")

    failing = EvidenceService(
        repository=repository,
        object_store=objects,
        security=security,
        event_store=event_store,
        privacy=policy.privacy,
        analyzers=(_Failing(),),
    )

    view = failing.analyze_evidence(investigator, context, CASE, ingested, "BROKEN")

    assert view.result.state is ResultState.FAILED
    assert view.payload is None
    assert repository.get_run(view.result.run_id).status is RunStatus.FAILED
    assert repository.get_current_result(ingested, "BROKEN") is None


def test_view_never_creates_a_processing_run(
    service, repository, investigator, context, ingested
):
    for _ in range(3):
        service.view_evidence(investigator, context, CASE, ingested)
    service.get_analysis_result(investigator, context, CASE, ingested, CDR_SUMMARY)

    assert repository.list_runs(ingested) == []


def test_analyze_reuses_an_existing_current_result(
    service, repository, investigator, context, ingested
):
    first = service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)
    second = service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)

    assert second.reused is True
    assert second.result.result_id == first.result.result_id
    assert len(repository.list_runs(ingested)) == 1


def test_reanalyze_creates_a_new_run_and_keeps_the_old_result(
    service, repository, investigator, context, ingested
):
    first = service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)
    second = service.reanalyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)

    assert second.reused is False
    assert second.result.run_id != first.result.run_id
    assert len(repository.list_runs(ingested)) == 2

    previous = repository.get_result(first.result.result_id)
    assert previous.state is ResultState.SUPERSEDED  # kept, not deleted
    assert repository.get_current_result(ingested, CDR_SUMMARY).result_id == second.result.result_id


def test_new_evidence_version_makes_existing_results_stale(
    service, repository, investigator, context, ingested
):
    first = service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)

    reingest(service, [{"caller": "+911111111111", "callee": "+912222222222"}])

    assert repository.get_result(first.result.result_id).state is ResultState.STALE
    assert repository.get_current_result(ingested, CDR_SUMMARY) is None
    assert service.get_analysis_result(investigator, context, CASE, ingested, CDR_SUMMARY) is None


def test_analyze_after_a_new_version_recomputes_rather_than_reusing(
    service, repository, investigator, context, ingested
):
    first = service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)
    reingest(service, [{"caller": "+911111111111", "callee": "+912222222222"}])

    second = service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)

    assert second.reused is False
    assert second.result.evidence_version_id != first.result.evidence_version_id
    assert second.payload["record_count"] == 1


def test_explicit_invalidation_marks_a_result_stale(
    service, repository, investigator, context, ingested
):
    view = service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)

    repository.mark_result_state(view.result.result_id, ResultState.STALE)

    assert repository.get_result(view.result.result_id).state is ResultState.STALE
    assert repository.get_current_result(ingested, CDR_SUMMARY) is None


def test_unknown_evidence_is_not_found(service, investigator, context):
    with pytest.raises(EvidenceNotFound):
        service.view_evidence(investigator, context, CASE, "EV-DOES-NOT-EXIST")


# -- audit -----------------------------------------------------------------


def test_ingestion_and_view_are_audited(service, event_store, investigator, context, ingested):
    service.view_evidence(investigator, context, CASE, ingested)

    assert len(event_store.list_by_type(FlightRecorderEvent.EVIDENCE_CREATED)) == 2
    assert len(event_store.list_by_type(FlightRecorderEvent.EVIDENCE_VERSION_CREATED)) == 2
    viewed = event_store.list_by_type(FlightRecorderEvent.EVIDENCE_VIEWED)
    assert len(viewed) == 1
    assert viewed[0].payload["evidence_id"] == ingested
    assert viewed[0].case_id == CASE.id


def test_analysis_and_reanalysis_are_audited(
    service, event_store, investigator, context, ingested
):
    service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)
    service.analyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)
    service.reanalyze_evidence(investigator, context, CASE, ingested, CDR_SUMMARY)

    assert len(event_store.list_by_type(FlightRecorderEvent.EVIDENCE_ANALYSIS_STARTED)) == 1
    assert len(event_store.list_by_type(FlightRecorderEvent.EVIDENCE_ANALYSIS_REUSED)) == 1
    assert len(event_store.list_by_type(FlightRecorderEvent.EVIDENCE_REANALYZED)) == 1
    assert len(event_store.list_by_type(FlightRecorderEvent.EVIDENCE_ANALYSIS_COMPLETED)) == 2


# -- authorization and masking --------------------------------------------


def test_denied_access_never_returns_a_payload(service, grants, context, ingested):
    stranger = make_user(user_id="USR-777", level="L3")  # no agency or case grant

    with pytest.raises(EvidenceAccessDenied) as denial:
        service.view_evidence(stranger, make_context(user_id="USR-777", level="L3"), CASE, ingested)

    assert denial.value.decision.is_denied
    assert not hasattr(denial.value, "payload")
    assert "records" not in str(denial.value)


def test_partial_authorization_masks_the_payload(service, grants, ingested):
    """An L2 investigator may read the CDR, but not the identifiers in it."""
    limited = make_user(user_id="USR-500", level="L2")
    grants.grant_agency(limited.id, POLICE.id)
    grants.grant_case(limited.id, POLICE.id, CASE.id, need_to_know=True)

    view = service.view_evidence(
        limited, make_context(user_id="USR-500", level="L2"), CASE, ingested
    )

    assert view.decision.effect.value == "PARTIAL"
    assert set(view.masked_fields) == {"caller", "callee", "imei", "imsi"}
    row = view.payload["records"][0]
    assert row["caller"] == "+91-XXXX-3210"
    assert row["callee"] == "+91-XXXX-5678"
    assert row["imei"] == "***"
    assert row["imsi"] == "***"
    assert row["cell_id"] == "MH-PUNE-0442"  # not sensitive, untouched
    assert "+919876543210" not in json.dumps(view.payload)


def test_full_clearance_sees_unmasked_payload(service, investigator, context, ingested):
    view = service.view_evidence(investigator, context, CASE, ingested)

    assert view.masked_fields == ()
    assert view.payload["records"][0]["caller"] == "+919876543210"


def test_masked_view_is_audited_as_redaction(service, grants, event_store, ingested):
    limited = make_user(user_id="USR-500", level="L2")
    grants.grant_agency(limited.id, POLICE.id)
    grants.grant_case(limited.id, POLICE.id, CASE.id, need_to_know=True)

    service.view_evidence(limited, make_context(user_id="USR-500", level="L2"), CASE, ingested)

    assert len(event_store.list_by_type(FlightRecorderEvent.EVIDENCE_REDACTED)) == 1
