"""Evidence lifecycle service.

The core rule this file exists to enforce:

    VIEW never processes. ANALYZE reuses a current result. REANALYZE is the only
    operation that deliberately creates new work.

An investigator can therefore move through a case freely — opening a CDR for the
tenth time costs nothing and changes nothing.

Order of operations is also load-bearing: authorization happens *before* any
payload is read from the object store, so a denial never touches protected
content, and a PARTIAL decision is applied here rather than handed to a client
as raw data plus a request to hide it.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from app.core.audit.event_store import ActorType, EventDraft, EventStore, FlightRecorderEvent
from app.core.domain.agency import AgencyContext
from app.core.domain.authorization import AuthorizationDecision
from app.core.domain.case import Case
from app.core.domain.identity import User
from app.core.evidence.analysis import AnalyzerError, EvidenceAnalyzer
from app.core.evidence.models import (
    AnalysisResult,
    EvidenceRecord,
    EvidenceState,
    EvidenceVersion,
    ProcessingRun,
    ResultState,
    RunStatus,
    TrustClassification,
)
from app.core.evidence.object_store import EvidenceObjectStore
from app.core.evidence.repository import EvidenceRepository
from app.core.evidence.source import EvidenceSource
from app.infrastructure.clock import utc_now_iso
from app.infrastructure.logging import current_correlation_id
from app.security.privacy.masking import mask_payload
from app.security.privacy.policy import PrivacyPolicy
from app.security.service import SecurityService

ACTION_VIEW_EVIDENCE = "VIEW_EVIDENCE"
ACTION_ANALYZE_EVIDENCE = "ANALYZE_EVIDENCE"
ACTION_REANALYZE_EVIDENCE = "REANALYZE_EVIDENCE"


class EvidenceAccessDenied(Exception):
    """Raised when authorization denies access. Carries no protected payload."""

    def __init__(self, decision: AuthorizationDecision) -> None:
        super().__init__(decision.reason.value)
        self.decision = decision


class EvidenceNotFound(Exception):
    """Raised when evidence, a version or a result does not exist."""


@dataclass(frozen=True)
class EvidenceView:
    evidence: EvidenceRecord
    version: EvidenceVersion
    payload: Mapping[str, Any]  # already masked when the decision was PARTIAL
    decision: AuthorizationDecision
    masked_fields: tuple[str, ...]


@dataclass(frozen=True)
class AnalysisView:
    result: AnalysisResult
    payload: Mapping[str, Any] | None
    reused: bool  # True when an existing current result was returned unchanged
    decision: AuthorizationDecision


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Deterministic serialisation, so the same content always hashes the same."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def evidence_id_for(case_id: str, source_id: str, source_record_id: str) -> str:
    """Deterministic id, so re-ingesting the same source record yields a version, not a duplicate."""
    digest = sha256_hex(f"{case_id}|{source_id}|{source_record_id}".encode("utf-8"))
    return f"EV-{digest[:12].upper()}"


class EvidenceService:
    def __init__(
        self,
        repository: EvidenceRepository,
        object_store: EvidenceObjectStore,
        security: SecurityService,
        event_store: EventStore,
        privacy: PrivacyPolicy,
        analyzers: Iterable[EvidenceAnalyzer] = (),
        clock: Callable[[], str] = utc_now_iso,
    ) -> None:
        self._repository = repository
        self._objects = object_store
        self._security = security
        self._events = event_store
        self._privacy = privacy
        self._analyzers = {analyzer.task_type: analyzer for analyzer in analyzers}
        self._clock = clock

    # -- ingestion --------------------------------------------------------

    def ingest_from_source(
        self, case: Case, source: EvidenceSource, actor_id: str = "SYSTEM"
    ) -> list[EvidenceRecord]:
        """Ingest a source's records, creating evidence and versions as needed.

        Re-ingesting unchanged content is a no-op; changed content becomes a new
        version rather than an overwrite.
        """
        correlation = current_correlation_id()
        ingested: list[EvidenceRecord] = []

        for item in source.fetch(case.id):
            evidence_id = evidence_id_for(case.id, source.source_id, item.source_record_id)
            payload_bytes = canonical_bytes(item.payload)
            content_hash = sha256_hex(payload_bytes)
            now = self._clock()

            record = self._repository.get_evidence(evidence_id)
            if record is None:
                record = self._repository.create_evidence(
                    EvidenceRecord(
                        id=evidence_id,
                        case_id=case.id,
                        source_id=source.source_id,
                        source_record_id=item.source_record_id,
                        classification=item.classification,
                        state=EvidenceState.INGESTED,
                        created_at=now,
                        security_level=item.security_level,
                        sensitive_fields=item.sensitive_fields,
                    )
                )
                self._record(
                    FlightRecorderEvent.EVIDENCE_CREATED,
                    actor_id,
                    case.id,
                    correlation,
                    {
                        "evidence_id": evidence_id,
                        "source_id": source.source_id,
                        "source_record_id": item.source_record_id,
                        "classification": item.classification.value,
                    },
                )

            latest = self._repository.get_latest_version(evidence_id)
            if latest is not None and latest.content_hash == content_hash:
                continue  # unchanged content: reuse the existing version

            number = 1 if latest is None else latest.version_number + 1
            reference = self._objects.put(
                (case.id, evidence_id, f"v{number}", "source.json"), payload_bytes
            )
            version = self._repository.create_version(
                EvidenceVersion(
                    version_id=f"{evidence_id}-v{number}",
                    evidence_id=evidence_id,
                    version_number=number,
                    content_hash=content_hash,
                    payload_ref=reference,
                    source_reference=item.source_reference,
                    ingested_at=now,
                )
            )
            self._repository.set_evidence_state(evidence_id, EvidenceState.AVAILABLE)
            self._record(
                FlightRecorderEvent.EVIDENCE_VERSION_CREATED,
                actor_id,
                case.id,
                correlation,
                {
                    "evidence_id": evidence_id,
                    "version_id": version.version_id,
                    "version_number": number,
                    "content_hash": content_hash,
                },
            )
            ingested.append(record)
        return ingested

    # -- read paths -------------------------------------------------------

    def list_case_evidence(
        self, user: User, context: AgencyContext, case: Case
    ) -> list[EvidenceRecord]:
        """Metadata listing, gated on case access. Returns no payloads."""
        decision = self._security.authorize_case_access(user, context, case)
        if not decision.grants_access:
            raise EvidenceAccessDenied(decision)
        return self._repository.list_evidence_for_case(case.id)

    def view_evidence(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        evidence_id: str,
        version_id: str | None = None,
    ) -> EvidenceView:
        """Retrieve existing evidence. Never starts a processing run."""
        evidence = self._require_evidence(case, evidence_id)
        decision = self._authorize(user, context, case, evidence, ACTION_VIEW_EVIDENCE)

        version = (
            self._repository.get_version(version_id)
            if version_id
            else self._repository.get_latest_version(evidence_id)
        )
        if version is None or version.evidence_id != evidence_id:
            raise EvidenceNotFound(f"no such version for evidence '{evidence_id}'")

        payload = json.loads(self._objects.get(version.payload_ref))
        masked_fields = decision.redacted_fields
        if masked_fields:
            payload = self._mask_records(payload, masked_fields)

        self._record(
            FlightRecorderEvent.EVIDENCE_VIEWED,
            user.id,
            case.id,
            decision.correlation_id,
            {
                "evidence_id": evidence_id,
                "version_id": version.version_id,
                "decision": decision.effect.value,
                "redacted_fields": list(masked_fields),
            },
        )
        return EvidenceView(
            evidence=evidence,
            version=version,
            payload=payload,
            decision=decision,
            masked_fields=masked_fields,
        )

    def get_evidence_versions(
        self, user: User, context: AgencyContext, case: Case, evidence_id: str
    ) -> list[EvidenceVersion]:
        evidence = self._require_evidence(case, evidence_id)
        self._authorize(user, context, case, evidence, ACTION_VIEW_EVIDENCE)
        return self._repository.list_versions(evidence_id)

    def get_analysis_result(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        evidence_id: str,
        task_type: str,
    ) -> AnalysisView | None:
        """Return the current result if one exists. Never starts a run."""
        evidence = self._require_evidence(case, evidence_id)
        decision = self._authorize(user, context, case, evidence, ACTION_VIEW_EVIDENCE)

        result = self._repository.get_current_result(evidence_id, task_type)
        if result is None:
            return None
        return AnalysisView(
            result=result,
            payload=self._result_payload(result, decision),
            reused=True,
            decision=decision,
        )

    # -- processing -------------------------------------------------------

    def analyze_evidence(
        self, user: User, context: AgencyContext, case: Case, evidence_id: str, task_type: str
    ) -> AnalysisView:
        """Return the current result if there is one, otherwise run the analysis."""
        evidence = self._require_evidence(case, evidence_id)
        decision = self._authorize(user, context, case, evidence, ACTION_ANALYZE_EVIDENCE)
        version = self._require_latest_version(evidence_id)

        current = self._repository.get_current_result(evidence_id, task_type)
        if current is not None and current.evidence_version_id == version.version_id:
            self._record(
                FlightRecorderEvent.EVIDENCE_ANALYSIS_REUSED,
                user.id,
                case.id,
                decision.correlation_id,
                {
                    "evidence_id": evidence_id,
                    "task_type": task_type,
                    "result_id": current.result_id,
                },
            )
            return AnalysisView(
                result=current,
                payload=self._result_payload(current, decision),
                reused=True,
                decision=decision,
            )

        return self._execute(user, case, evidence_id, version, task_type, decision, reanalysis=False)

    def reanalyze_evidence(
        self, user: User, context: AgencyContext, case: Case, evidence_id: str, task_type: str
    ) -> AnalysisView:
        """Always create a new processing run; the previous result is kept as SUPERSEDED."""
        evidence = self._require_evidence(case, evidence_id)
        decision = self._authorize(user, context, case, evidence, ACTION_REANALYZE_EVIDENCE)
        version = self._require_latest_version(evidence_id)
        return self._execute(user, case, evidence_id, version, task_type, decision, reanalysis=True)

    def _execute(
        self,
        user: User,
        case: Case,
        evidence_id: str,
        version: EvidenceVersion,
        task_type: str,
        decision: AuthorizationDecision,
        reanalysis: bool,
    ) -> AnalysisView:
        analyzer = self._analyzers.get(task_type)
        if analyzer is None:
            raise EvidenceNotFound(f"no analyzer registered for task type '{task_type}'")

        run_id = f"RUN-{uuid.uuid4().hex[:12].upper()}"
        run = self._repository.create_run(
            ProcessingRun(
                run_id=run_id,
                evidence_id=evidence_id,
                evidence_version_id=version.version_id,
                task_type=task_type,
                status=RunStatus.RUNNING,
                started_at=self._clock(),
                workflow_version=analyzer.workflow_version,
                rule_version=analyzer.rule_version,
                input_hash=version.content_hash,
                correlation_id=decision.correlation_id,
            )
        )
        self._record(
            FlightRecorderEvent.EVIDENCE_REANALYZED
            if reanalysis
            else FlightRecorderEvent.EVIDENCE_ANALYSIS_STARTED,
            user.id,
            case.id,
            decision.correlation_id,
            {
                "evidence_id": evidence_id,
                "version_id": version.version_id,
                "task_type": task_type,
                "run_id": run.run_id,
            },
        )

        source_payload = json.loads(self._objects.get(version.payload_ref))
        try:
            output = analyzer.analyze(source_payload)
        except (AnalyzerError, ValueError, TypeError, KeyError) as exc:
            return self._fail(user, case, evidence_id, version, task_type, run, decision, exc)

        output_bytes = canonical_bytes(output)
        output_hash = sha256_hex(output_bytes)
        reference = self._objects.put(
            (case.id, evidence_id, f"v{version.version_number}", f"{run.run_id}.result.json"),
            output_bytes,
        )
        self._repository.finish_run(
            run.run_id, RunStatus.COMPLETED, self._clock(), output_hash=output_hash
        )
        result = self._repository.save_result(
            AnalysisResult(
                result_id=f"RES-{run.run_id[4:]}",
                run_id=run.run_id,
                evidence_id=evidence_id,
                evidence_version_id=version.version_id,
                task_type=task_type,
                # Computed over observed data, so DERIVED — never OBSERVED.
                classification=TrustClassification.DERIVED,
                state=ResultState.CURRENT,
                output_hash=output_hash,
                payload_ref=reference,
                created_at=self._clock(),
            )
        )
        self._record(
            FlightRecorderEvent.EVIDENCE_ANALYSIS_COMPLETED,
            user.id,
            case.id,
            decision.correlation_id,
            {
                "evidence_id": evidence_id,
                "task_type": task_type,
                "run_id": run.run_id,
                "result_id": result.result_id,
                "output_hash": output_hash,
            },
        )
        return AnalysisView(
            result=result,
            payload=self._result_payload(result, decision),
            reused=False,
            decision=decision,
        )

    def _fail(
        self,
        user: User,
        case: Case,
        evidence_id: str,
        version: EvidenceVersion,
        task_type: str,
        run: ProcessingRun,
        decision: AuthorizationDecision,
        exc: Exception,
    ) -> AnalysisView:
        """Record the failure. A failed run never produces a CURRENT result."""
        error_code = type(exc).__name__
        self._repository.finish_run(
            run.run_id, RunStatus.FAILED, self._clock(), error_code=error_code
        )
        result = self._repository.save_result(
            AnalysisResult(
                result_id=f"RES-{run.run_id[4:]}",
                run_id=run.run_id,
                evidence_id=evidence_id,
                evidence_version_id=version.version_id,
                task_type=task_type,
                classification=TrustClassification.DERIVED,
                state=ResultState.FAILED,
                output_hash=None,
                payload_ref=None,
                created_at=self._clock(),
            )
        )
        self._record(
            FlightRecorderEvent.EVIDENCE_ANALYSIS_FAILED,
            user.id,
            case.id,
            decision.correlation_id,
            {
                "evidence_id": evidence_id,
                "task_type": task_type,
                "run_id": run.run_id,
                "error_code": error_code,
            },
        )
        return AnalysisView(result=result, payload=None, reused=False, decision=decision)

    # -- helpers ----------------------------------------------------------

    def _authorize(
        self,
        user: User,
        context: AgencyContext,
        case: Case,
        evidence: EvidenceRecord,
        action: str,
    ) -> AuthorizationDecision:
        decision = self._security.authorize_evidence_access(
            user, context, case, evidence, action
        )
        if not decision.grants_access:
            raise EvidenceAccessDenied(decision)
        return decision

    def _require_evidence(self, case: Case, evidence_id: str) -> EvidenceRecord:
        evidence = self._repository.get_evidence(evidence_id)
        if evidence is None or evidence.case_id != case.id:
            raise EvidenceNotFound(f"no such evidence '{evidence_id}' in case '{case.id}'")
        return evidence

    def _require_latest_version(self, evidence_id: str) -> EvidenceVersion:
        version = self._repository.get_latest_version(evidence_id)
        if version is None:
            raise EvidenceNotFound(f"evidence '{evidence_id}' has no versions")
        return version

    def _result_payload(
        self, result: AnalysisResult, decision: AuthorizationDecision
    ) -> Mapping[str, Any] | None:
        if result.payload_ref is None:
            return None
        payload = json.loads(self._objects.get(result.payload_ref))
        if decision.redacted_fields:
            payload = self._mask(payload, decision.redacted_fields)
        return payload

    def _mask_records(
        self, payload: Mapping[str, Any], fields: tuple[str, ...]
    ) -> dict[str, Any]:
        """Mask the top level and any nested `records` rows, which hold the identifiers."""
        masked = self._mask(payload, fields)
        records = payload.get("records")
        if isinstance(records, list):
            masked["records"] = [
                self._mask(row, fields) if isinstance(row, Mapping) else row for row in records
            ]
        return masked

    def _mask(self, payload: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
        return mask_payload(payload, fields, self._privacy.partial_mask_fields)

    def _record(
        self,
        event_type: FlightRecorderEvent,
        actor_id: str,
        case_id: str,
        correlation_id: str,
        payload: dict[str, Any],
    ) -> None:
        self._events.append(
            EventDraft(
                event_type=event_type,
                actor_id=actor_id,
                actor_type=ActorType.USER,
                correlation_id=correlation_id,
                case_id=case_id,
                payload=payload,
            )
        )
