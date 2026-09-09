"""SQLite implementation of EvidenceDebtRepository.

Owns the two transitions no caller should have to remember:

- saving an item whose facts changed inserts a new version and marks the
  previous ones SUPERSEDED, so what the engine concluded before stays readable;
- saving an item whose facts are unchanged returns the stored record untouched,
  so a recalculation over unchanged state writes nothing at all.

The live version of an item is simply its highest version number. There is no
"is_live" flag to fall out of step with the rows it describes.

A snapshot stores its top items as their serialised explanation rather than as
ids, for the same reason a signal stores its metrics: a total read back in a
year is unexplainable on its own, and an item the current detectors no longer
produce would otherwise become unreadable history.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.core.debt.models import (
    DebtBand,
    DebtBlocker,
    DebtCategory,
    DebtReason,
    DebtSeverity,
    DebtStatus,
    DebtSubject,
    DebtSubjectType,
    DebtWeighting,
    EvidenceDebtBreakdown,
    EvidenceDebtItem,
    EvidenceDebtSnapshot,
)
from app.core.debt.repository import EvidenceDebtRepositoryError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_debt_snapshots (
    snapshot_id             TEXT PRIMARY KEY,
    case_id                 TEXT NOT NULL,
    calculated_at           TEXT NOT NULL,
    calculated_by           TEXT NOT NULL,
    correlation_id          TEXT NOT NULL,
    total_debt              REAL NOT NULL,
    normalized_debt         REAL NOT NULL,
    band                    TEXT NOT NULL,
    item_count              INTEGER NOT NULL,
    breakdown               TEXT NOT NULL,
    top_items               TEXT NOT NULL,
    debt_ids                TEXT NOT NULL,
    evidence_in_scope       INTEGER NOT NULL,
    excluded_evidence_count INTEGER NOT NULL,
    scope_fingerprint       TEXT NOT NULL,
    policy_version          TEXT NOT NULL,
    debt_engine_version     TEXT NOT NULL,
    sequence                INTEGER
);
CREATE INDEX IF NOT EXISTS idx_debt_snapshots_case
    ON evidence_debt_snapshots (case_id, scope_fingerprint, sequence);

CREATE TABLE IF NOT EXISTS evidence_debt_items (
    debt_id                 TEXT NOT NULL,
    scope_fingerprint       TEXT NOT NULL,
    version                 INTEGER NOT NULL,
    case_id                 TEXT NOT NULL,
    category                TEXT NOT NULL,
    severity                TEXT NOT NULL,
    status                  TEXT NOT NULL,
    reason                  TEXT NOT NULL,
    subject_type            TEXT NOT NULL,
    subject_reference       TEXT NOT NULL,
    entity_refs             TEXT NOT NULL,
    weighting               TEXT NOT NULL,
    explanation             TEXT NOT NULL,
    supporting_evidence_ids TEXT NOT NULL,
    related_resolution_ids  TEXT NOT NULL,
    related_finding_ids     TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    calculated_at           TEXT NOT NULL,
    policy_version          TEXT NOT NULL,
    debt_engine_version     TEXT NOT NULL,
    actionable              INTEGER NOT NULL,
    priority                INTEGER NOT NULL,
    blocking_reason         TEXT NOT NULL,
    required_capability     TEXT,
    fact_fingerprint        TEXT NOT NULL,
    status_changed_at       TEXT,
    status_changed_by       TEXT,
    status_reason           TEXT,
    sequence                INTEGER,
    PRIMARY KEY (debt_id, scope_fingerprint, version)
);
CREATE INDEX IF NOT EXISTS idx_debt_items_case
    ON evidence_debt_items (case_id, scope_fingerprint, status);
"""

#: Selects only the live version of each item — the highest version recorded for
#: a (debt_id, scope) pair.
_LIVE_VERSION = (
    "version = (SELECT MAX(x.version) FROM evidence_debt_items x "
    "WHERE x.debt_id = evidence_debt_items.debt_id "
    "AND x.scope_fingerprint = evidence_debt_items.scope_fingerprint)"
)


class SQLiteEvidenceDebtRepository:
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

    # -- snapshots --------------------------------------------------------

    def save_snapshot(self, snapshot: EvidenceDebtSnapshot) -> EvidenceDebtSnapshot:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO evidence_debt_snapshots (snapshot_id, case_id, "
                    "calculated_at, calculated_by, correlation_id, total_debt, "
                    "normalized_debt, band, item_count, breakdown, top_items, debt_ids, "
                    "evidence_in_scope, excluded_evidence_count, scope_fingerprint, "
                    "policy_version, debt_engine_version, sequence) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "(SELECT COALESCE(MAX(sequence), 0) + 1 FROM evidence_debt_snapshots))",
                    (
                        snapshot.snapshot_id,
                        snapshot.case_id,
                        snapshot.calculated_at,
                        snapshot.calculated_by,
                        snapshot.correlation_id,
                        snapshot.total_debt,
                        snapshot.normalized_debt,
                        snapshot.band.value,
                        snapshot.item_count,
                        _dump([_breakdown_dict(entry) for entry in snapshot.breakdown]),
                        _dump([_item_dict(item) for item in snapshot.top_items]),
                        _dump(list(snapshot.debt_ids)),
                        snapshot.evidence_in_scope,
                        snapshot.excluded_evidence_count,
                        snapshot.scope_fingerprint,
                        snapshot.policy_version,
                        snapshot.debt_engine_version,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise EvidenceDebtRepositoryError(
                f"snapshot '{snapshot.snapshot_id}' already exists"
            ) from exc
        return _persisted(snapshot)

    def get_snapshot(self, snapshot_id: str) -> EvidenceDebtSnapshot | None:
        row = self._fetch_one(
            "SELECT * FROM evidence_debt_snapshots WHERE snapshot_id = ?", (snapshot_id,)
        )
        return None if row is None else _to_snapshot(row)

    def latest_snapshot(
        self, case_id: str, scope_fingerprint: str
    ) -> EvidenceDebtSnapshot | None:
        row = self._fetch_one(
            "SELECT * FROM evidence_debt_snapshots WHERE case_id = ? "
            "AND scope_fingerprint = ? ORDER BY sequence DESC LIMIT 1",
            (case_id, scope_fingerprint),
        )
        return None if row is None else _to_snapshot(row)

    def list_snapshots(
        self, case_id: str, scope_fingerprint: str | None = None
    ) -> list[EvidenceDebtSnapshot]:
        clauses = ["case_id = ?"]
        parameters: list[Any] = [case_id]
        if scope_fingerprint is not None:
            clauses.append("scope_fingerprint = ?")
            parameters.append(scope_fingerprint)
        rows = self._fetch_all(
            f"SELECT * FROM evidence_debt_snapshots WHERE {' AND '.join(clauses)} "
            "ORDER BY sequence",
            tuple(parameters),
        )
        return [_to_snapshot(row) for row in rows]

    # -- items ------------------------------------------------------------

    def save_item(self, item: EvidenceDebtItem) -> EvidenceDebtItem:
        """Insert a new version, or return the stored one when nothing changed."""
        try:
            with self._lock, self._connection:
                current = self._connection.execute(
                    "SELECT * FROM evidence_debt_items WHERE debt_id = ? "
                    "AND scope_fingerprint = ? ORDER BY version DESC LIMIT 1",
                    (item.debt_id, item.scope_fingerprint),
                ).fetchone()
                if current is not None and current["fact_fingerprint"] == item.fact_fingerprint:
                    return _to_item(current)

                version = 0 if current is None else int(current["version"])
                created_at = item.created_at if current is None else current["created_at"]
                self._connection.execute(
                    "UPDATE evidence_debt_items SET status = ? "
                    "WHERE debt_id = ? AND scope_fingerprint = ? AND status != ?",
                    (
                        DebtStatus.SUPERSEDED.value,
                        item.debt_id,
                        item.scope_fingerprint,
                        DebtStatus.SUPERSEDED.value,
                    ),
                )
                stored = _with_version(item, version + 1, created_at)
                self._connection.execute(
                    "INSERT INTO evidence_debt_items (debt_id, scope_fingerprint, version, "
                    "case_id, category, severity, status, reason, subject_type, "
                    "subject_reference, entity_refs, weighting, explanation, "
                    "supporting_evidence_ids, related_resolution_ids, related_finding_ids, "
                    "created_at, calculated_at, policy_version, debt_engine_version, "
                    "actionable, priority, blocking_reason, required_capability, "
                    "fact_fingerprint, status_changed_at, status_changed_by, status_reason, "
                    "sequence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "(SELECT COALESCE(MAX(sequence), 0) + 1 FROM evidence_debt_items))",
                    (
                        stored.debt_id,
                        stored.scope_fingerprint,
                        stored.version,
                        stored.case_id,
                        stored.category.value,
                        stored.severity.value,
                        stored.status.value,
                        stored.reason.value,
                        stored.subject.subject_type.value,
                        stored.subject.reference,
                        _dump(list(stored.subject.entity_refs)),
                        _dump(_weighting_dict(stored.weighting)),
                        _dump(dict(stored.explanation)),
                        _dump(list(stored.supporting_evidence_ids)),
                        _dump(list(stored.related_resolution_ids)),
                        _dump(list(stored.related_finding_ids)),
                        stored.created_at,
                        stored.calculated_at,
                        stored.policy_version,
                        stored.debt_engine_version,
                        1 if stored.actionable else 0,
                        stored.priority,
                        stored.blocking_reason.value,
                        stored.required_capability,
                        stored.fact_fingerprint,
                        stored.status_changed_at,
                        stored.status_changed_by,
                        stored.status_reason,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise EvidenceDebtRepositoryError(
                f"debt item '{item.debt_id}' version conflict"
            ) from exc
        return stored

    def get_item(self, debt_id: str, scope_fingerprint: str) -> EvidenceDebtItem | None:
        row = self._fetch_one(
            "SELECT * FROM evidence_debt_items WHERE debt_id = ? AND scope_fingerprint = ? "
            "ORDER BY version DESC LIMIT 1",
            (debt_id, scope_fingerprint),
        )
        return None if row is None else _to_item(row)

    def list_items(
        self,
        case_id: str,
        categories: Sequence[DebtCategory] | None = None,
        statuses: Sequence[DebtStatus] | None = None,
        scope_fingerprint: str | None = None,
    ) -> list[EvidenceDebtItem]:
        clauses = ["case_id = ?", _LIVE_VERSION]
        parameters: list[Any] = [case_id]
        if scope_fingerprint is not None:
            clauses.append("scope_fingerprint = ?")
            parameters.append(scope_fingerprint)
        if categories:
            clauses.append(f"category IN ({', '.join('?' for _ in categories)})")
            parameters.extend(category.value for category in categories)
        if statuses:
            clauses.append(f"status IN ({', '.join('?' for _ in statuses)})")
            parameters.extend(status.value for status in statuses)
        rows = self._fetch_all(
            f"SELECT * FROM evidence_debt_items WHERE {' AND '.join(clauses)} "
            "ORDER BY debt_id",
            tuple(parameters),
        )
        items = [_to_item(row) for row in rows]
        return sorted(items, key=lambda item: (-item.contribution, item.debt_id))

    def list_item_history(
        self, debt_id: str, scope_fingerprint: str
    ) -> list[EvidenceDebtItem]:
        rows = self._fetch_all(
            "SELECT * FROM evidence_debt_items WHERE debt_id = ? AND scope_fingerprint = ? "
            "ORDER BY version",
            (debt_id, scope_fingerprint),
        )
        return [_to_item(row) for row in rows]

    def update_item_status(
        self,
        debt_id: str,
        scope_fingerprint: str,
        status: DebtStatus,
        changed_at: str,
        changed_by: str,
        reason: str | None = None,
    ) -> EvidenceDebtItem:
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM evidence_debt_items WHERE debt_id = ? "
                "AND scope_fingerprint = ? ORDER BY version DESC LIMIT 1",
                (debt_id, scope_fingerprint),
            ).fetchone()
            if row is None:
                raise EvidenceDebtRepositoryError(f"no debt item '{debt_id}' in this scope")
            self._connection.execute(
                "UPDATE evidence_debt_items SET status = ?, status_changed_at = ?, "
                "status_changed_by = ?, status_reason = ? "
                "WHERE debt_id = ? AND scope_fingerprint = ? AND version = ?",
                (
                    status.value,
                    changed_at,
                    changed_by,
                    reason,
                    debt_id,
                    scope_fingerprint,
                    int(row["version"]),
                ),
            )
        updated = self.get_item(debt_id, scope_fingerprint)
        if updated is None:  # pragma: no cover - the row was just written
            raise EvidenceDebtRepositoryError(f"debt item '{debt_id}' vanished on update")
        return updated

    # -- plumbing ---------------------------------------------------------

    def _fetch_one(self, sql: str, parameters: tuple) -> sqlite3.Row | None:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchone()
        except sqlite3.Error as exc:
            raise EvidenceDebtRepositoryError(f"failed to read debt state: {exc}") from exc

    def _fetch_all(self, sql: str, parameters: tuple) -> list[sqlite3.Row]:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchall()
        except sqlite3.Error as exc:
            raise EvidenceDebtRepositoryError(f"failed to read debt state: {exc}") from exc


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _with_version(
    item: EvidenceDebtItem, version: int, created_at: str
) -> EvidenceDebtItem:
    from dataclasses import replace

    return replace(item, version=version, created_at=created_at)


def _persisted(snapshot: EvidenceDebtSnapshot) -> EvidenceDebtSnapshot:
    from dataclasses import replace

    return replace(snapshot, persisted=True)


def _weighting_dict(weighting: DebtWeighting) -> dict[str, Any]:
    return {
        "category_weight": weighting.category_weight,
        "severity_multiplier": weighting.severity_multiplier,
        "scope_factor": weighting.scope_factor,
        "criticality_factor": weighting.criticality_factor,
        "affected_scope": weighting.affected_scope,
        "weighted_contribution": weighting.weighted_contribution,
    }


def _to_weighting(data: Mapping[str, Any]) -> DebtWeighting:
    return DebtWeighting(
        category_weight=float(data["category_weight"]),
        severity_multiplier=float(data["severity_multiplier"]),
        scope_factor=float(data["scope_factor"]),
        criticality_factor=float(data["criticality_factor"]),
        affected_scope=int(data["affected_scope"]),
        weighted_contribution=float(data["weighted_contribution"]),
    )


def _breakdown_dict(entry: EvidenceDebtBreakdown) -> dict[str, Any]:
    return {
        "category": entry.category.value,
        "item_count": entry.item_count,
        "weighted_contribution": entry.weighted_contribution,
        "share": entry.share,
        "severity_counts": dict(entry.severity_counts),
    }


def _to_breakdown(data: Mapping[str, Any]) -> EvidenceDebtBreakdown:
    return EvidenceDebtBreakdown(
        category=DebtCategory(data["category"]),
        item_count=int(data["item_count"]),
        weighted_contribution=float(data["weighted_contribution"]),
        share=float(data["share"]),
        severity_counts={str(k): int(v) for k, v in data["severity_counts"].items()},
    )


def _item_dict(item: EvidenceDebtItem) -> dict[str, Any]:
    return {
        "debt_id": item.debt_id,
        "case_id": item.case_id,
        "category": item.category.value,
        "severity": item.severity.value,
        "status": item.status.value,
        "reason": item.reason.value,
        "subject_type": item.subject.subject_type.value,
        "subject_reference": item.subject.reference,
        "entity_refs": list(item.subject.entity_refs),
        "weighting": _weighting_dict(item.weighting),
        "explanation": dict(item.explanation),
        "supporting_evidence_ids": list(item.supporting_evidence_ids),
        "related_resolution_ids": list(item.related_resolution_ids),
        "related_finding_ids": list(item.related_finding_ids),
        "created_at": item.created_at,
        "calculated_at": item.calculated_at,
        "policy_version": item.policy_version,
        "debt_engine_version": item.debt_engine_version,
        "actionable": item.actionable,
        "priority": item.priority,
        "blocking_reason": item.blocking_reason.value,
        "required_capability": item.required_capability,
        "scope_fingerprint": item.scope_fingerprint,
        "version": item.version,
        "fact_fingerprint": item.fact_fingerprint,
        "status_changed_at": item.status_changed_at,
        "status_changed_by": item.status_changed_by,
        "status_reason": item.status_reason,
    }


def _item_from_dict(data: Mapping[str, Any]) -> EvidenceDebtItem:
    return EvidenceDebtItem(
        debt_id=data["debt_id"],
        case_id=data["case_id"],
        category=DebtCategory(data["category"]),
        severity=DebtSeverity(data["severity"]),
        status=DebtStatus(data["status"]),
        reason=DebtReason(data["reason"]),
        subject=DebtSubject(
            subject_type=DebtSubjectType(data["subject_type"]),
            reference=data["subject_reference"],
            entity_refs=tuple(data["entity_refs"]),
        ),
        weighting=_to_weighting(data["weighting"]),
        explanation=dict(data["explanation"]),
        supporting_evidence_ids=tuple(data["supporting_evidence_ids"]),
        related_resolution_ids=tuple(data["related_resolution_ids"]),
        related_finding_ids=tuple(data["related_finding_ids"]),
        created_at=data["created_at"],
        calculated_at=data["calculated_at"],
        policy_version=data["policy_version"],
        debt_engine_version=data["debt_engine_version"],
        actionable=bool(data["actionable"]),
        priority=int(data["priority"]),
        blocking_reason=DebtBlocker(data["blocking_reason"]),
        required_capability=data["required_capability"],
        scope_fingerprint=data["scope_fingerprint"],
        version=int(data["version"]),
        fact_fingerprint=data["fact_fingerprint"],
        status_changed_at=data["status_changed_at"],
        status_changed_by=data["status_changed_by"],
        status_reason=data["status_reason"],
    )


def _to_item(row: sqlite3.Row) -> EvidenceDebtItem:
    return EvidenceDebtItem(
        debt_id=row["debt_id"],
        case_id=row["case_id"],
        category=DebtCategory(row["category"]),
        severity=DebtSeverity(row["severity"]),
        status=DebtStatus(row["status"]),
        reason=DebtReason(row["reason"]),
        subject=DebtSubject(
            subject_type=DebtSubjectType(row["subject_type"]),
            reference=row["subject_reference"],
            entity_refs=tuple(json.loads(row["entity_refs"])),
        ),
        weighting=_to_weighting(json.loads(row["weighting"])),
        explanation=json.loads(row["explanation"]),
        supporting_evidence_ids=tuple(json.loads(row["supporting_evidence_ids"])),
        related_resolution_ids=tuple(json.loads(row["related_resolution_ids"])),
        related_finding_ids=tuple(json.loads(row["related_finding_ids"])),
        created_at=row["created_at"],
        calculated_at=row["calculated_at"],
        policy_version=row["policy_version"],
        debt_engine_version=row["debt_engine_version"],
        actionable=bool(row["actionable"]),
        priority=int(row["priority"]),
        blocking_reason=DebtBlocker(row["blocking_reason"]),
        required_capability=row["required_capability"],
        scope_fingerprint=row["scope_fingerprint"],
        version=int(row["version"]),
        fact_fingerprint=row["fact_fingerprint"],
        status_changed_at=row["status_changed_at"],
        status_changed_by=row["status_changed_by"],
        status_reason=row["status_reason"],
    )


def _to_snapshot(row: sqlite3.Row) -> EvidenceDebtSnapshot:
    return EvidenceDebtSnapshot(
        snapshot_id=row["snapshot_id"],
        case_id=row["case_id"],
        calculated_at=row["calculated_at"],
        calculated_by=row["calculated_by"],
        correlation_id=row["correlation_id"],
        total_debt=float(row["total_debt"]),
        normalized_debt=float(row["normalized_debt"]),
        band=DebtBand(row["band"]),
        item_count=int(row["item_count"]),
        breakdown=tuple(_to_breakdown(entry) for entry in json.loads(row["breakdown"])),
        top_items=tuple(_item_from_dict(entry) for entry in json.loads(row["top_items"])),
        debt_ids=tuple(json.loads(row["debt_ids"])),
        evidence_in_scope=int(row["evidence_in_scope"]),
        excluded_evidence_count=int(row["excluded_evidence_count"]),
        scope_fingerprint=row["scope_fingerprint"],
        policy_version=row["policy_version"],
        debt_engine_version=row["debt_engine_version"],
        persisted=True,
    )
