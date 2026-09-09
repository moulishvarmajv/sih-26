"""SQLite implementation of AnalyticsRepository.

Owns the supersede transition so no caller has to remember it: saving a signal
whose identity already has an ACTIVE record marks that record SUPERSEDED and
inserts the new one a version higher. Nothing is deleted or updated in place
except that one status flip.

Metrics are stored as their serialised explanation rather than as a bare score,
for the same reason a resolution stores its evidence: a number read back in a
year is unexplainable on its own, and a signal that cannot be explained is not
usable in an investigation.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.core.analytics.models import (
    AnalyticsEntity,
    AnalyticsRun,
    InvestigationSignal,
    SignalMetric,
    SignalReason,
    SignalStatus,
    SignalType,
)
from app.core.analytics.repository import AnalyticsRepositoryError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analytics_runs (
    run_id                  TEXT PRIMARY KEY,
    case_id                 TEXT NOT NULL,
    analytics_version       TEXT NOT NULL,
    executed_at             TEXT NOT NULL,
    executed_by             TEXT NOT NULL,
    correlation_id          TEXT NOT NULL,
    evidence_ids            TEXT NOT NULL,
    node_count              INTEGER NOT NULL,
    relationship_count      INTEGER NOT NULL,
    signal_count            INTEGER NOT NULL,
    excluded_evidence_count INTEGER NOT NULL,
    truncated               INTEGER NOT NULL,
    sequence                INTEGER
);
CREATE INDEX IF NOT EXISTS idx_analytics_runs_case ON analytics_runs (case_id, sequence);

CREATE TABLE IF NOT EXISTS analytics_signals (
    signal_id                    TEXT NOT NULL,
    version                      INTEGER NOT NULL,
    case_id                      TEXT NOT NULL,
    signal_type                  TEXT NOT NULL,
    entities                     TEXT NOT NULL,
    score                        REAL NOT NULL,
    confidence                   TEXT NOT NULL,
    reasons                      TEXT NOT NULL,
    metrics                      TEXT NOT NULL,
    supporting_relationship_ids  TEXT NOT NULL,
    supporting_evidence_ids      TEXT NOT NULL,
    detail                       TEXT NOT NULL,
    created_at                   TEXT NOT NULL,
    analytics_version            TEXT NOT NULL,
    run_id                       TEXT NOT NULL,
    status                       TEXT NOT NULL,
    sequence                     INTEGER,
    PRIMARY KEY (signal_id, version)
);
CREATE INDEX IF NOT EXISTS idx_analytics_signals_case
    ON analytics_signals (case_id, status, score);
"""


class SQLiteAnalyticsRepository:
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

    # -- runs -------------------------------------------------------------

    def save_run(self, run: AnalyticsRun) -> AnalyticsRun:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO analytics_runs (run_id, case_id, analytics_version, "
                    "executed_at, executed_by, correlation_id, evidence_ids, node_count, "
                    "relationship_count, signal_count, excluded_evidence_count, truncated, "
                    "sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "(SELECT COALESCE(MAX(sequence), 0) + 1 FROM analytics_runs))",
                    (
                        run.run_id,
                        run.case_id,
                        run.analytics_version,
                        run.executed_at,
                        run.executed_by,
                        run.correlation_id,
                        json.dumps(list(run.evidence_ids), separators=(",", ":")),
                        run.node_count,
                        run.relationship_count,
                        run.signal_count,
                        run.excluded_evidence_count,
                        1 if run.truncated else 0,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AnalyticsRepositoryError(f"run '{run.run_id}' already exists") from exc
        return run

    def get_run(self, run_id: str) -> AnalyticsRun | None:
        row = self._fetch_one("SELECT * FROM analytics_runs WHERE run_id = ?", (run_id,))
        return None if row is None else _to_run(row)

    def list_runs(self, case_id: str) -> list[AnalyticsRun]:
        rows = self._fetch_all(
            "SELECT * FROM analytics_runs WHERE case_id = ? ORDER BY sequence", (case_id,)
        )
        return [_to_run(row) for row in rows]

    # -- signals ----------------------------------------------------------

    def save_signal(self, signal: InvestigationSignal) -> InvestigationSignal:
        """Insert a signal, superseding whatever was active for its identity."""
        try:
            with self._lock, self._connection:
                current = self._connection.execute(
                    "SELECT MAX(version) AS version FROM analytics_signals WHERE signal_id = ?",
                    (signal.signal_id,),
                ).fetchone()
                version = (current["version"] or 0) + 1
                self._connection.execute(
                    "UPDATE analytics_signals SET status = ? "
                    "WHERE signal_id = ? AND status = ?",
                    (SignalStatus.SUPERSEDED.value, signal.signal_id, SignalStatus.ACTIVE.value),
                )
                stored = _with_version(signal, version)
                self._connection.execute(
                    "INSERT INTO analytics_signals (signal_id, version, case_id, signal_type, "
                    "entities, score, confidence, reasons, metrics, "
                    "supporting_relationship_ids, supporting_evidence_ids, detail, created_at, "
                    "analytics_version, run_id, status, sequence) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "(SELECT COALESCE(MAX(sequence), 0) + 1 FROM analytics_signals))",
                    (
                        stored.signal_id,
                        stored.version,
                        stored.case_id,
                        stored.signal_type.value,
                        _dump([_entity_dict(entity) for entity in stored.entities]),
                        stored.score,
                        stored.confidence,
                        _dump([reason.value for reason in stored.reasons]),
                        _dump([_metric_dict(metric) for metric in stored.metrics]),
                        _dump(list(stored.supporting_relationship_ids)),
                        _dump(list(stored.supporting_evidence_ids)),
                        _dump(stored.detail),
                        stored.created_at,
                        stored.analytics_version,
                        stored.run_id,
                        stored.status.value,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AnalyticsRepositoryError(
                f"signal '{signal.signal_id}' version conflict"
            ) from exc
        return stored

    def get_signal(self, signal_id: str) -> InvestigationSignal | None:
        """The active record for an identity, or the latest if none is active."""
        row = self._fetch_one(
            "SELECT * FROM analytics_signals WHERE signal_id = ? "
            "ORDER BY CASE status WHEN 'ACTIVE' THEN 0 ELSE 1 END, version DESC LIMIT 1",
            (signal_id,),
        )
        return None if row is None else _to_signal(row)

    def list_signals(
        self,
        case_id: str,
        signal_types: Sequence[SignalType] | None = None,
        active_only: bool = True,
    ) -> list[InvestigationSignal]:
        clauses = ["case_id = ?"]
        parameters: list[Any] = [case_id]
        if active_only:
            clauses.append("status = ?")
            parameters.append(SignalStatus.ACTIVE.value)
        if signal_types:
            placeholders = ", ".join("?" for _ in signal_types)
            clauses.append(f"signal_type IN ({placeholders})")
            parameters.extend(signal_type.value for signal_type in signal_types)
        rows = self._fetch_all(
            f"SELECT * FROM analytics_signals WHERE {' AND '.join(clauses)} "
            "ORDER BY score DESC, signal_id",
            tuple(parameters),
        )
        return [_to_signal(row) for row in rows]

    def list_signal_history(self, signal_id: str) -> list[InvestigationSignal]:
        rows = self._fetch_all(
            "SELECT * FROM analytics_signals WHERE signal_id = ? ORDER BY version",
            (signal_id,),
        )
        return [_to_signal(row) for row in rows]

    # -- plumbing ---------------------------------------------------------

    def _fetch_one(self, sql: str, parameters: tuple) -> sqlite3.Row | None:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchone()
        except sqlite3.Error as exc:
            raise AnalyticsRepositoryError(f"failed to read analytics state: {exc}") from exc

    def _fetch_all(self, sql: str, parameters: tuple) -> list[sqlite3.Row]:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchall()
        except sqlite3.Error as exc:
            raise AnalyticsRepositoryError(f"failed to read analytics state: {exc}") from exc


def _with_version(signal: InvestigationSignal, version: int) -> InvestigationSignal:
    from dataclasses import replace

    return replace(signal, version=version, status=SignalStatus.ACTIVE)


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _entity_dict(entity: AnalyticsEntity) -> dict[str, str]:
    return {
        "entity_id": entity.entity_id,
        "entity_type": entity.entity_type,
        "label": entity.label,
    }


def _metric_dict(metric: SignalMetric) -> dict[str, Any]:
    return {
        "name": metric.name,
        "value": metric.value,
        "normalized": metric.normalized,
        "weight": metric.weight,
        "contribution": metric.contribution,
    }


def _to_run(row: sqlite3.Row) -> AnalyticsRun:
    return AnalyticsRun(
        run_id=row["run_id"],
        case_id=row["case_id"],
        analytics_version=row["analytics_version"],
        executed_at=row["executed_at"],
        executed_by=row["executed_by"],
        correlation_id=row["correlation_id"],
        evidence_ids=tuple(json.loads(row["evidence_ids"])),
        node_count=int(row["node_count"]),
        relationship_count=int(row["relationship_count"]),
        signal_count=int(row["signal_count"]),
        excluded_evidence_count=int(row["excluded_evidence_count"]),
        truncated=bool(row["truncated"]),
    )


def _to_signal(row: sqlite3.Row) -> InvestigationSignal:
    entities: list[Mapping[str, str]] = json.loads(row["entities"])
    metrics: list[Mapping[str, Any]] = json.loads(row["metrics"])
    return InvestigationSignal(
        signal_id=row["signal_id"],
        case_id=row["case_id"],
        signal_type=SignalType(row["signal_type"]),
        entities=tuple(
            AnalyticsEntity(
                entity_id=entity["entity_id"],
                entity_type=entity["entity_type"],
                label=entity["label"],
            )
            for entity in entities
        ),
        score=float(row["score"]),
        confidence=row["confidence"],
        reasons=tuple(SignalReason(reason) for reason in json.loads(row["reasons"])),
        metrics=tuple(
            SignalMetric(
                name=metric["name"],
                value=float(metric["value"]),
                normalized=float(metric["normalized"]),
                weight=float(metric["weight"]),
                contribution=float(metric["contribution"]),
            )
            for metric in metrics
        ),
        supporting_relationship_ids=tuple(json.loads(row["supporting_relationship_ids"])),
        supporting_evidence_ids=tuple(json.loads(row["supporting_evidence_ids"])),
        created_at=row["created_at"],
        analytics_version=row["analytics_version"],
        run_id=row["run_id"],
        version=int(row["version"]),
        status=SignalStatus(row["status"]),
        detail=json.loads(row["detail"]),
    )
