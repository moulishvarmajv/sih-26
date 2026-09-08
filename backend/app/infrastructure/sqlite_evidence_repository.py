"""SQLite implementation of EvidenceRepository.

Owns the supersede/stale transitions so no caller has to remember them:

- a new version supersedes the previous CURRENT version and makes results
  computed from it STALE (kept, still readable, still auditable);
- a new CURRENT result supersedes the previous CURRENT one for the same
  (evidence, task_type).

Nothing is ever deleted or overwritten in place; history is retained.
"""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from app.core.evidence.models import (
    AnalysisResult,
    EvidenceRecord,
    EvidenceState,
    EvidenceVersion,
    ProcessingRun,
    ResultState,
    RunStatus,
    TrustClassification,
    VersionState,
)
from app.core.evidence.repository import EvidenceRepositoryError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id      TEXT PRIMARY KEY,
    case_id          TEXT NOT NULL,
    source_id        TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    classification   TEXT NOT NULL,
    state            TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    security_level   TEXT,
    sensitive_fields TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence (case_id);

CREATE TABLE IF NOT EXISTS evidence_versions (
    version_id       TEXT PRIMARY KEY,
    evidence_id      TEXT NOT NULL,
    version_number   INTEGER NOT NULL,
    content_hash     TEXT NOT NULL,
    payload_ref      TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    ingested_at      TEXT NOT NULL,
    state            TEXT NOT NULL,
    UNIQUE (evidence_id, version_number)
);
CREATE INDEX IF NOT EXISTS idx_versions_evidence ON evidence_versions (evidence_id, version_number);

CREATE TABLE IF NOT EXISTS processing_runs (
    run_id              TEXT PRIMARY KEY,
    evidence_id         TEXT NOT NULL,
    evidence_version_id TEXT NOT NULL,
    task_type           TEXT NOT NULL,
    status              TEXT NOT NULL,
    started_at          TEXT NOT NULL,
    completed_at        TEXT,
    workflow_version    TEXT NOT NULL,
    rule_version        TEXT NOT NULL,
    input_hash          TEXT NOT NULL,
    output_hash         TEXT,
    error_code          TEXT,
    correlation_id      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_evidence ON processing_runs (evidence_id, started_at);

CREATE TABLE IF NOT EXISTS analysis_results (
    result_id           TEXT PRIMARY KEY,
    run_id              TEXT NOT NULL,
    evidence_id         TEXT NOT NULL,
    evidence_version_id TEXT NOT NULL,
    task_type           TEXT NOT NULL,
    classification      TEXT NOT NULL,
    state               TEXT NOT NULL,
    output_hash         TEXT,
    payload_ref         TEXT,
    created_at          TEXT NOT NULL,
    sequence            INTEGER
);
CREATE INDEX IF NOT EXISTS idx_results_current
    ON analysis_results (evidence_id, task_type, state);
"""


class SQLiteEvidenceRepository:
    def __init__(self, database_path: str | Path) -> None:
        self._lock = threading.Lock()
        path = str(database_path)
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock, self._connection:
            self._connection.executescript(_SCHEMA)

    def close(self) -> None:
        self._connection.close()

    # -- evidence ---------------------------------------------------------

    def create_evidence(self, record: EvidenceRecord) -> EvidenceRecord:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO evidence (evidence_id, case_id, source_id, source_record_id, "
                    "classification, state, created_at, security_level, sensitive_fields) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        record.id,
                        record.case_id,
                        record.source_id,
                        record.source_record_id,
                        record.classification.value,
                        record.state.value,
                        record.created_at,
                        record.security_level,
                        ",".join(record.sensitive_fields),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise EvidenceRepositoryError(f"evidence '{record.id}' already exists") from exc
        return record

    def get_evidence(self, evidence_id: str) -> EvidenceRecord | None:
        row = self._fetch_one("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
        return None if row is None else _to_evidence(row)

    def list_evidence_for_case(self, case_id: str) -> list[EvidenceRecord]:
        rows = self._fetch_all(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY created_at, evidence_id",
            (case_id,),
        )
        return [_to_evidence(row) for row in rows]

    def set_evidence_state(self, evidence_id: str, state: EvidenceState) -> None:
        self._execute(
            "UPDATE evidence SET state = ? WHERE evidence_id = ?", (state.value, evidence_id)
        )

    # -- versions ---------------------------------------------------------

    def create_version(self, version: EvidenceVersion) -> EvidenceVersion:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    "UPDATE evidence_versions SET state = ? WHERE evidence_id = ? AND state = ?",
                    (VersionState.SUPERSEDED.value, version.evidence_id, VersionState.CURRENT.value),
                )
                # Results computed from a superseded version no longer reflect
                # current evidence, but stay readable for audit.
                self._connection.execute(
                    "UPDATE analysis_results SET state = ? "
                    "WHERE evidence_id = ? AND state = ?",
                    (ResultState.STALE.value, version.evidence_id, ResultState.CURRENT.value),
                )
                self._connection.execute(
                    "INSERT INTO evidence_versions (version_id, evidence_id, version_number, "
                    "content_hash, payload_ref, source_reference, ingested_at, state) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        version.version_id,
                        version.evidence_id,
                        version.version_number,
                        version.content_hash,
                        version.payload_ref,
                        version.source_reference,
                        version.ingested_at,
                        VersionState.CURRENT.value,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise EvidenceRepositoryError(
                f"version '{version.version_id}' already exists"
            ) from exc
        return version

    def get_version(self, version_id: str) -> EvidenceVersion | None:
        row = self._fetch_one(
            "SELECT * FROM evidence_versions WHERE version_id = ?", (version_id,)
        )
        return None if row is None else _to_version(row)

    def get_latest_version(self, evidence_id: str) -> EvidenceVersion | None:
        row = self._fetch_one(
            "SELECT * FROM evidence_versions WHERE evidence_id = ? "
            "ORDER BY version_number DESC LIMIT 1",
            (evidence_id,),
        )
        return None if row is None else _to_version(row)

    def list_versions(self, evidence_id: str) -> list[EvidenceVersion]:
        rows = self._fetch_all(
            "SELECT * FROM evidence_versions WHERE evidence_id = ? ORDER BY version_number",
            (evidence_id,),
        )
        return [_to_version(row) for row in rows]

    # -- runs -------------------------------------------------------------

    def create_run(self, run: ProcessingRun) -> ProcessingRun:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO processing_runs (run_id, evidence_id, evidence_version_id, "
                    "task_type, status, started_at, completed_at, workflow_version, rule_version, "
                    "input_hash, output_hash, error_code, correlation_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        run.run_id,
                        run.evidence_id,
                        run.evidence_version_id,
                        run.task_type,
                        run.status.value,
                        run.started_at,
                        run.completed_at,
                        run.workflow_version,
                        run.rule_version,
                        run.input_hash,
                        run.output_hash,
                        run.error_code,
                        run.correlation_id,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise EvidenceRepositoryError(f"run '{run.run_id}' already exists") from exc
        return run

    def finish_run(
        self,
        run_id: str,
        status: RunStatus,
        completed_at: str,
        output_hash: str | None = None,
        error_code: str | None = None,
    ) -> ProcessingRun:
        self._execute(
            "UPDATE processing_runs SET status = ?, completed_at = ?, output_hash = ?, "
            "error_code = ? WHERE run_id = ?",
            (status.value, completed_at, output_hash, error_code, run_id),
        )
        run = self.get_run(run_id)
        if run is None:
            raise EvidenceRepositoryError(f"unknown run '{run_id}'")
        return run

    def get_run(self, run_id: str) -> ProcessingRun | None:
        row = self._fetch_one("SELECT * FROM processing_runs WHERE run_id = ?", (run_id,))
        return None if row is None else _to_run(row)

    def list_runs(self, evidence_id: str) -> list[ProcessingRun]:
        rows = self._fetch_all(
            "SELECT * FROM processing_runs WHERE evidence_id = ? ORDER BY started_at, run_id",
            (evidence_id,),
        )
        return [_to_run(row) for row in rows]

    # -- results ----------------------------------------------------------

    def save_result(self, result: AnalysisResult) -> AnalysisResult:
        try:
            with self._lock, self._connection:
                if result.state is ResultState.CURRENT:
                    self._connection.execute(
                        "UPDATE analysis_results SET state = ? "
                        "WHERE evidence_id = ? AND task_type = ? AND state = ?",
                        (
                            ResultState.SUPERSEDED.value,
                            result.evidence_id,
                            result.task_type,
                            ResultState.CURRENT.value,
                        ),
                    )
                self._connection.execute(
                    "INSERT INTO analysis_results (result_id, run_id, evidence_id, "
                    "evidence_version_id, task_type, classification, state, output_hash, "
                    "payload_ref, created_at, sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "(SELECT COALESCE(MAX(sequence), 0) + 1 FROM analysis_results))",
                    (
                        result.result_id,
                        result.run_id,
                        result.evidence_id,
                        result.evidence_version_id,
                        result.task_type,
                        result.classification.value,
                        result.state.value,
                        result.output_hash,
                        result.payload_ref,
                        result.created_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise EvidenceRepositoryError(f"result '{result.result_id}' already exists") from exc
        return result

    def get_result(self, result_id: str) -> AnalysisResult | None:
        row = self._fetch_one("SELECT * FROM analysis_results WHERE result_id = ?", (result_id,))
        return None if row is None else _to_result(row)

    def get_current_result(self, evidence_id: str, task_type: str) -> AnalysisResult | None:
        row = self._fetch_one(
            "SELECT * FROM analysis_results WHERE evidence_id = ? AND task_type = ? "
            "AND state = ? ORDER BY sequence DESC LIMIT 1",
            (evidence_id, task_type, ResultState.CURRENT.value),
        )
        return None if row is None else _to_result(row)

    def list_results(self, evidence_id: str) -> list[AnalysisResult]:
        rows = self._fetch_all(
            "SELECT * FROM analysis_results WHERE evidence_id = ? ORDER BY sequence",
            (evidence_id,),
        )
        return [_to_result(row) for row in rows]

    def mark_result_state(self, result_id: str, state: ResultState) -> None:
        self._execute(
            "UPDATE analysis_results SET state = ? WHERE result_id = ?", (state.value, result_id)
        )

    # -- plumbing ---------------------------------------------------------

    def _execute(self, sql: str, parameters: tuple) -> None:
        try:
            with self._lock, self._connection:
                self._connection.execute(sql, parameters)
        except sqlite3.Error as exc:
            raise EvidenceRepositoryError(f"failed to write evidence state: {exc}") from exc

    def _fetch_one(self, sql: str, parameters: tuple) -> sqlite3.Row | None:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchone()
        except sqlite3.Error as exc:
            raise EvidenceRepositoryError(f"failed to read evidence state: {exc}") from exc

    def _fetch_all(self, sql: str, parameters: tuple) -> list[sqlite3.Row]:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchall()
        except sqlite3.Error as exc:
            raise EvidenceRepositoryError(f"failed to read evidence state: {exc}") from exc


def _to_evidence(row: sqlite3.Row) -> EvidenceRecord:
    raw_fields = row["sensitive_fields"]
    return EvidenceRecord(
        id=row["evidence_id"],
        case_id=row["case_id"],
        source_id=row["source_id"],
        source_record_id=row["source_record_id"],
        classification=TrustClassification(row["classification"]),
        state=EvidenceState(row["state"]),
        created_at=row["created_at"],
        security_level=row["security_level"],
        sensitive_fields=tuple(raw_fields.split(",")) if raw_fields else (),
    )


def _to_version(row: sqlite3.Row) -> EvidenceVersion:
    return EvidenceVersion(
        version_id=row["version_id"],
        evidence_id=row["evidence_id"],
        version_number=int(row["version_number"]),
        content_hash=row["content_hash"],
        payload_ref=row["payload_ref"],
        source_reference=row["source_reference"],
        ingested_at=row["ingested_at"],
        state=VersionState(row["state"]),
    )


def _to_run(row: sqlite3.Row) -> ProcessingRun:
    return ProcessingRun(
        run_id=row["run_id"],
        evidence_id=row["evidence_id"],
        evidence_version_id=row["evidence_version_id"],
        task_type=row["task_type"],
        status=RunStatus(row["status"]),
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        workflow_version=row["workflow_version"],
        rule_version=row["rule_version"],
        input_hash=row["input_hash"],
        output_hash=row["output_hash"],
        error_code=row["error_code"],
        correlation_id=row["correlation_id"],
    )


def _to_result(row: sqlite3.Row) -> AnalysisResult:
    return AnalysisResult(
        result_id=row["result_id"],
        run_id=row["run_id"],
        evidence_id=row["evidence_id"],
        evidence_version_id=row["evidence_version_id"],
        task_type=row["task_type"],
        classification=TrustClassification(row["classification"]),
        state=ResultState(row["state"]),
        output_hash=row["output_hash"],
        payload_ref=row["payload_ref"],
        created_at=row["created_at"],
    )
