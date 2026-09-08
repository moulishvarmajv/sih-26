"""Synthetic CDR evidence source.

Reads a controlled local dataset — no network, no external service. Each export
becomes one evidence item; its records are normalised but never cleaned up:
duplicates, inconsistent formatting and an IMEI seen with two IMSIs are all
preserved exactly as observed. Deciding what those mean is analysis, not
ingestion, and OBSERVED evidence must keep what the source actually said.

Malformed records are rejected rather than guessed at.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from app.core.evidence.models import TrustClassification
from app.core.evidence.source import EvidenceSourceError, SourceEvidence

DEFAULT_DATASET = Path(__file__).with_name("synthetic_cdr_sample.json")

CDR_SENSITIVE_FIELDS = ("caller", "callee", "imei", "imsi")
_REQUIRED_FIELDS = ("caller", "callee", "timestamp", "imei", "imsi")
_OPTIONAL_FIELDS = ("cell_id", "subscriber_id")


class SyntheticCDRSource:
    source_id = "SYNTHETIC_CDR"

    def __init__(
        self, dataset_path: str | Path = DEFAULT_DATASET, security_level: str = "L2"
    ) -> None:
        self._dataset_path = Path(dataset_path)
        self._security_level = security_level

    def fetch(self, case_id: str) -> Iterable[SourceEvidence]:
        document = self._load()
        exports = document.get("exports")
        if not isinstance(exports, list):
            raise EvidenceSourceError("dataset has no 'exports' list")

        emitted = []
        for export in exports:
            if not isinstance(export, Mapping):
                raise EvidenceSourceError("export entry is not an object")
            if export.get("case_id") != case_id:
                continue
            emitted.append(self._to_evidence(export, document))
        return emitted

    def _load(self) -> Mapping[str, Any]:
        try:
            document = json.loads(self._dataset_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise EvidenceSourceError(f"dataset not found at {self._dataset_path}") from exc
        except json.JSONDecodeError as exc:
            raise EvidenceSourceError(f"dataset is not valid JSON: {exc}") from exc
        if not isinstance(document, Mapping):
            raise EvidenceSourceError("dataset must be a JSON object")
        return document

    def _to_evidence(
        self, export: Mapping[str, Any], document: Mapping[str, Any]
    ) -> SourceEvidence:
        export_id = export.get("export_id")
        if not isinstance(export_id, str) or not export_id:
            raise EvidenceSourceError("export is missing 'export_id'")

        records = export.get("records")
        if not isinstance(records, list) or not records:
            raise EvidenceSourceError(f"export '{export_id}' has no records")

        normalised = [normalise_record(record, export_id, index) for index, record in enumerate(records)]

        return SourceEvidence(
            source_record_id=export_id,
            payload={
                "export_id": export_id,
                "operator": export.get("operator"),
                "record_count": len(normalised),
                "records": normalised,
            },
            classification=TrustClassification.OBSERVED,
            source_reference=f"{document.get('dataset', 'unknown')}:{export_id}",
            security_level=self._security_level,
            sensitive_fields=CDR_SENSITIVE_FIELDS,
        )


def normalise_record(record: Any, export_id: str, index: int) -> dict[str, Any]:
    """Validate one CDR row and return it in canonical field order.

    Formatting is preserved verbatim: normalising `919876543210` into
    `+919876543210` here would silently rewrite what the operator reported.
    """
    where = f"{export_id}[{index}]"
    if not isinstance(record, Mapping):
        raise EvidenceSourceError(f"{where}: record is not an object")

    for field in _REQUIRED_FIELDS:
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            raise EvidenceSourceError(f"{where}: missing or invalid '{field}'")

    duration = record.get("duration_seconds")
    if not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
        raise EvidenceSourceError(f"{where}: 'duration_seconds' must be a non-negative integer")

    normalised = {field: record[field] for field in _REQUIRED_FIELDS}
    normalised["duration_seconds"] = duration
    for field in _OPTIONAL_FIELDS:
        if field in record:
            normalised[field] = record[field]
    return normalised
