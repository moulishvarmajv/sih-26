"""SQLite implementation of ResolutionRepository.

Owns the supersede transition so no caller has to remember it: saving a decision
for a lineage that already has a live one marks the previous decision SUPERSEDED
and records which decision replaced it. Nothing is deleted or updated in place
except that one forward link and the terminal outcome of an open decision.

The score is stored as its serialised explanation rather than as a bare number,
so a decision read back years later still says which signals produced it and
under which policy version — a number alone would be unexplainable.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.core.resolution.models import (
    BlockingStrategy,
    ConfidenceBand,
    DecidedBy,
    EntityObservationRef,
    EntityResolutionCandidate,
    EntityResolutionDecision,
    EntityType,
    MatchEvidence,
    MatchScore,
    MatchSignal,
    ReasonCode,
    Recommendation,
    ResolutionConflict,
    ResolutionReview,
    ResolutionStatus,
    ReviewAction,
    SignalOutcome,
)
from app.core.resolution.repository import ResolutionRepositoryError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS resolution_candidates (
    candidate_id      TEXT PRIMARY KEY,
    case_id           TEXT NOT NULL,
    entity_type       TEXT NOT NULL,
    lineage_id        TEXT NOT NULL,
    left_observation  TEXT NOT NULL,
    right_observation TEXT NOT NULL,
    blocking_strategy TEXT NOT NULL,
    blocking_key      TEXT NOT NULL,
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_resolution_candidates_case
    ON resolution_candidates (case_id, created_at);

CREATE TABLE IF NOT EXISTS resolution_decisions (
    resolution_id     TEXT PRIMARY KEY,
    lineage_id        TEXT NOT NULL,
    resolution_version INTEGER NOT NULL,
    case_id           TEXT NOT NULL,
    entity_type       TEXT NOT NULL,
    candidate_id      TEXT NOT NULL,
    left_observation  TEXT NOT NULL,
    right_observation TEXT NOT NULL,
    status            TEXT NOT NULL,
    score             REAL NOT NULL,
    score_detail      TEXT NOT NULL,
    policy_version    TEXT NOT NULL,
    input_fingerprint TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    decided_at        TEXT,
    decided_by        TEXT,
    decision_actor    TEXT,
    decision_reason   TEXT,
    superseded_by     TEXT,
    sequence          INTEGER,
    UNIQUE (lineage_id, resolution_version)
);
CREATE INDEX IF NOT EXISTS idx_resolution_decisions_case
    ON resolution_decisions (case_id, status);
CREATE INDEX IF NOT EXISTS idx_resolution_decisions_lineage
    ON resolution_decisions (lineage_id, resolution_version);

CREATE TABLE IF NOT EXISTS resolution_reviews (
    review_id     TEXT PRIMARY KEY,
    resolution_id TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    reviewer_id   TEXT NOT NULL,
    action        TEXT NOT NULL,
    reviewed_at   TEXT NOT NULL,
    reason        TEXT,
    sequence      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_resolution_reviews_resolution
    ON resolution_reviews (resolution_id, sequence);
"""

#: Statuses a decision can still move on from. A superseded or already-decided
#: resolution is never reopened in place — a new version is created instead.
OPEN_STATUSES = (ResolutionStatus.REVIEW_REQUIRED,)

#: A lineage has at most one of these at a time; saving a new decision for the
#: lineage supersedes whichever one is live.
LIVE_STATUSES = (
    ResolutionStatus.CANDIDATE,
    ResolutionStatus.AUTO_ACCEPTED,
    ResolutionStatus.REVIEW_REQUIRED,
    ResolutionStatus.APPROVED,
    ResolutionStatus.REJECTED,
)


class SQLiteResolutionRepository:
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

    # -- candidates -------------------------------------------------------

    def save_candidate(self, candidate: EntityResolutionCandidate) -> EntityResolutionCandidate:
        self._execute(
            "INSERT OR IGNORE INTO resolution_candidates (candidate_id, case_id, entity_type, "
            "lineage_id, left_observation, right_observation, blocking_strategy, blocking_key, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                candidate.candidate_id,
                candidate.case_id,
                candidate.entity_type.value,
                candidate.lineage_id,
                _dump_ref(candidate.left),
                _dump_ref(candidate.right),
                candidate.blocking_strategy.value,
                candidate.blocking_key,
                candidate.created_at,
            ),
        )
        return candidate

    def get_candidate(self, candidate_id: str) -> EntityResolutionCandidate | None:
        row = self._fetch_one(
            "SELECT * FROM resolution_candidates WHERE candidate_id = ?", (candidate_id,)
        )
        return None if row is None else _to_candidate(row)

    def list_candidates(self, case_id: str) -> list[EntityResolutionCandidate]:
        rows = self._fetch_all(
            "SELECT * FROM resolution_candidates WHERE case_id = ? "
            "ORDER BY created_at, candidate_id",
            (case_id,),
        )
        return [_to_candidate(row) for row in rows]

    # -- decisions --------------------------------------------------------

    def save_decision(self, decision: EntityResolutionDecision) -> EntityResolutionDecision:
        placeholders = ", ".join("?" for _ in LIVE_STATUSES)
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    f"UPDATE resolution_decisions SET status = ?, superseded_by = ? "
                    f"WHERE lineage_id = ? AND status IN ({placeholders})",
                    (
                        ResolutionStatus.SUPERSEDED.value,
                        decision.resolution_id,
                        decision.lineage_id,
                        *[status.value for status in LIVE_STATUSES],
                    ),
                )
                self._connection.execute(
                    "INSERT INTO resolution_decisions (resolution_id, lineage_id, "
                    "resolution_version, case_id, entity_type, candidate_id, left_observation, "
                    "right_observation, status, score, score_detail, policy_version, "
                    "input_fingerprint, created_at, decided_at, decided_by, decision_actor, "
                    "decision_reason, superseded_by, sequence) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "(SELECT COALESCE(MAX(sequence), 0) + 1 FROM resolution_decisions))",
                    (
                        decision.resolution_id,
                        decision.lineage_id,
                        decision.resolution_version,
                        decision.case_id,
                        decision.entity_type.value,
                        decision.candidate_id,
                        _dump_ref(decision.left),
                        _dump_ref(decision.right),
                        decision.status.value,
                        decision.score.score,
                        _dump_score(decision.score),
                        decision.policy_version,
                        decision.input_fingerprint,
                        decision.created_at,
                        decision.decided_at,
                        decision.decided_by,
                        None if decision.decision_actor is None else decision.decision_actor.value,
                        decision.decision_reason,
                        decision.superseded_by,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ResolutionRepositoryError(
                f"resolution '{decision.resolution_id}' already exists"
            ) from exc
        return decision

    def get_decision(self, resolution_id: str) -> EntityResolutionDecision | None:
        row = self._fetch_one(
            "SELECT * FROM resolution_decisions WHERE resolution_id = ?", (resolution_id,)
        )
        return None if row is None else _to_decision(row)

    def get_live_decision(self, lineage_id: str) -> EntityResolutionDecision | None:
        placeholders = ", ".join("?" for _ in LIVE_STATUSES)
        row = self._fetch_one(
            f"SELECT * FROM resolution_decisions WHERE lineage_id = ? "
            f"AND status IN ({placeholders}) ORDER BY resolution_version DESC LIMIT 1",
            (lineage_id, *[status.value for status in LIVE_STATUSES]),
        )
        return None if row is None else _to_decision(row)

    def list_decisions(
        self, case_id: str, statuses: Sequence[ResolutionStatus] | None = None
    ) -> list[EntityResolutionDecision]:
        if statuses is None:
            rows = self._fetch_all(
                "SELECT * FROM resolution_decisions WHERE case_id = ? ORDER BY sequence",
                (case_id,),
            )
        else:
            placeholders = ", ".join("?" for _ in statuses)
            rows = self._fetch_all(
                f"SELECT * FROM resolution_decisions WHERE case_id = ? "
                f"AND status IN ({placeholders}) ORDER BY sequence",
                (case_id, *[status.value for status in statuses]),
            )
        return [_to_decision(row) for row in rows]

    def list_lineage(self, lineage_id: str) -> list[EntityResolutionDecision]:
        rows = self._fetch_all(
            "SELECT * FROM resolution_decisions WHERE lineage_id = ? ORDER BY resolution_version",
            (lineage_id,),
        )
        return [_to_decision(row) for row in rows]

    def update_status(
        self,
        resolution_id: str,
        status: ResolutionStatus,
        decided_at: str,
        decided_by: str,
        decision_actor: str,
        decision_reason: str | None = None,
    ) -> EntityResolutionDecision:
        """Only an open decision may be closed, so a decided one is never overwritten."""
        placeholders = ", ".join("?" for _ in OPEN_STATUSES)
        with self._lock, self._connection:
            cursor = self._connection.execute(
                f"UPDATE resolution_decisions SET status = ?, decided_at = ?, decided_by = ?, "
                f"decision_actor = ?, decision_reason = ? "
                f"WHERE resolution_id = ? AND status IN ({placeholders})",
                (
                    status.value,
                    decided_at,
                    decided_by,
                    decision_actor,
                    decision_reason,
                    resolution_id,
                    *[state.value for state in OPEN_STATUSES],
                ),
            )
            changed = cursor.rowcount
        if changed == 0:
            raise ResolutionRepositoryError(
                f"resolution '{resolution_id}' is not open for a decision"
            )
        decision = self.get_decision(resolution_id)
        if decision is None:  # pragma: no cover - the update above just matched a row
            raise ResolutionRepositoryError(f"unknown resolution '{resolution_id}'")
        return decision

    # -- reviews ----------------------------------------------------------

    def add_review(self, review: ResolutionReview) -> ResolutionReview:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    "INSERT INTO resolution_reviews (review_id, resolution_id, case_id, "
                    "reviewer_id, action, reviewed_at, reason, sequence) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, "
                    "(SELECT COALESCE(MAX(sequence), 0) + 1 FROM resolution_reviews))",
                    (
                        review.review_id,
                        review.resolution_id,
                        review.case_id,
                        review.reviewer_id,
                        review.action.value,
                        review.reviewed_at,
                        review.reason,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ResolutionRepositoryError(
                f"review '{review.review_id}' already exists"
            ) from exc
        return review

    def list_reviews(self, resolution_id: str) -> list[ResolutionReview]:
        rows = self._fetch_all(
            "SELECT * FROM resolution_reviews WHERE resolution_id = ? ORDER BY sequence",
            (resolution_id,),
        )
        return [_to_review(row) for row in rows]

    # -- plumbing ---------------------------------------------------------

    def _execute(self, sql: str, parameters: tuple) -> None:
        try:
            with self._lock, self._connection:
                self._connection.execute(sql, parameters)
        except sqlite3.Error as exc:
            raise ResolutionRepositoryError(f"failed to write resolution state: {exc}") from exc

    def _fetch_one(self, sql: str, parameters: tuple) -> sqlite3.Row | None:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchone()
        except sqlite3.Error as exc:
            raise ResolutionRepositoryError(f"failed to read resolution state: {exc}") from exc

    def _fetch_all(self, sql: str, parameters: tuple) -> list[sqlite3.Row]:
        try:
            with self._lock:
                return self._connection.execute(sql, parameters).fetchall()
        except sqlite3.Error as exc:
            raise ResolutionRepositoryError(f"failed to read resolution state: {exc}") from exc


def _dump_ref(ref: EntityObservationRef) -> str:
    return json.dumps(
        {
            "observation_id": ref.observation_id,
            "entity_type": ref.entity_type.value,
            "entity_key": ref.entity_key,
            "source_id": ref.source_id,
            "evidence_id": ref.evidence_id,
            "evidence_version_id": ref.evidence_version_id,
            "observed_at": ref.observed_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _load_ref(raw: str) -> EntityObservationRef:
    data = json.loads(raw)
    return EntityObservationRef(
        observation_id=data["observation_id"],
        entity_type=EntityType(data["entity_type"]),
        entity_key=data["entity_key"],
        source_id=data["source_id"],
        evidence_id=data["evidence_id"],
        evidence_version_id=data["evidence_version_id"],
        observed_at=data["observed_at"],
    )


def _dump_score(score: MatchScore) -> str:
    return json.dumps(
        {
            "score": score.score,
            "evidence_weight": score.evidence_weight,
            "confidence": score.confidence.value,
            "confidence_floor": score.confidence_floor,
            "recommendation": score.recommendation.value,
            "policy_version": score.policy_version,
            "reasons": [reason.value for reason in score.reasons],
            "evidence": [
                {
                    "signal": item.signal.value,
                    "attribute": item.attribute,
                    "outcome": item.outcome.value,
                    "weight": item.weight,
                    "contribution": item.contribution,
                    "similarity": item.similarity,
                }
                for item in score.evidence
            ],
            "conflicts": [
                {
                    "attribute": conflict.attribute,
                    "rule": conflict.rule,
                    "penalty": conflict.penalty,
                    "blocks_auto_accept": conflict.blocks_auto_accept,
                    "similarity": conflict.similarity,
                }
                for conflict in score.conflicts
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _load_score(raw: str) -> MatchScore:
    data: Mapping[str, Any] = json.loads(raw)
    return MatchScore(
        score=float(data["score"]),
        evidence_weight=float(data["evidence_weight"]),
        confidence=ConfidenceBand(data["confidence"]),
        confidence_floor=float(data["confidence_floor"]),
        recommendation=Recommendation(data["recommendation"]),
        policy_version=data["policy_version"],
        reasons=tuple(ReasonCode(reason) for reason in data.get("reasons", ())),
        evidence=tuple(
            MatchEvidence(
                signal=MatchSignal(item["signal"]),
                attribute=item["attribute"],
                outcome=SignalOutcome(item["outcome"]),
                weight=float(item["weight"]),
                contribution=float(item["contribution"]),
                similarity=item.get("similarity"),
            )
            for item in data.get("evidence", ())
        ),
        conflicts=tuple(
            ResolutionConflict(
                attribute=conflict["attribute"],
                rule=conflict["rule"],
                penalty=float(conflict["penalty"]),
                blocks_auto_accept=bool(conflict["blocks_auto_accept"]),
                similarity=conflict.get("similarity"),
            )
            for conflict in data.get("conflicts", ())
        ),
    )


def _to_candidate(row: sqlite3.Row) -> EntityResolutionCandidate:
    return EntityResolutionCandidate(
        candidate_id=row["candidate_id"],
        case_id=row["case_id"],
        entity_type=EntityType(row["entity_type"]),
        lineage_id=row["lineage_id"],
        left=_load_ref(row["left_observation"]),
        right=_load_ref(row["right_observation"]),
        blocking_strategy=BlockingStrategy(row["blocking_strategy"]),
        blocking_key=row["blocking_key"],
        created_at=row["created_at"],
    )


def _to_decision(row: sqlite3.Row) -> EntityResolutionDecision:
    actor = row["decision_actor"]
    return EntityResolutionDecision(
        resolution_id=row["resolution_id"],
        lineage_id=row["lineage_id"],
        resolution_version=int(row["resolution_version"]),
        case_id=row["case_id"],
        entity_type=EntityType(row["entity_type"]),
        candidate_id=row["candidate_id"],
        left=_load_ref(row["left_observation"]),
        right=_load_ref(row["right_observation"]),
        status=ResolutionStatus(row["status"]),
        score=_load_score(row["score_detail"]),
        policy_version=row["policy_version"],
        input_fingerprint=row["input_fingerprint"],
        created_at=row["created_at"],
        decided_at=row["decided_at"],
        decided_by=row["decided_by"],
        decision_actor=None if actor is None else DecidedBy(actor),
        decision_reason=row["decision_reason"],
        superseded_by=row["superseded_by"],
    )


def _to_review(row: sqlite3.Row) -> ResolutionReview:
    return ResolutionReview(
        review_id=row["review_id"],
        resolution_id=row["resolution_id"],
        case_id=row["case_id"],
        reviewer_id=row["reviewer_id"],
        action=ReviewAction(row["action"]),
        reviewed_at=row["reviewed_at"],
        reason=row["reason"],
    )
