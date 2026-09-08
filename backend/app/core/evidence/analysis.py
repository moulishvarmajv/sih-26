"""Evidence analyzers.

An analyzer is a deterministic, versioned transformation of one evidence
payload. Determinism matters: the same version analysed twice must produce the
same output hash, otherwise reuse and comparison are meaningless.

Output is DERIVED, never OBSERVED — an analyzer computes over facts, it does not
witness them.

`CdrSummaryAnalyzer` is deliberately a structural summary, not CDR analytics:
it proves the lifecycle end to end. Real telecom analysis is a later phase.
"""
from __future__ import annotations

from typing import Any, Mapping, Protocol

CDR_SUMMARY = "CDR_SUMMARY"


class AnalyzerError(Exception):
    """Raised when a payload cannot be analysed."""


class EvidenceAnalyzer(Protocol):
    task_type: str
    workflow_version: str
    rule_version: str

    def analyze(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """Compute a deterministic result from one evidence payload."""
        ...


class CdrSummaryAnalyzer:
    """Aggregate counts over a CDR payload. Reports no identifiers, only shape."""

    task_type = CDR_SUMMARY
    workflow_version = "1.0.0"
    rule_version = "cdr-summary-1.0.0"

    def analyze(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        records = payload.get("records")
        if not isinstance(records, list):
            raise AnalyzerError("CDR payload has no 'records' list")

        callers, callees, imeis, timestamps = set(), set(), set(), []
        imei_to_imsi: dict[str, set[str]] = {}
        seen, duplicates = set(), 0
        total_duration = 0

        for record in records:
            if not isinstance(record, Mapping):
                raise AnalyzerError("CDR record is not an object")
            fingerprint = (
                record.get("caller"),
                record.get("callee"),
                record.get("timestamp"),
                record.get("imei"),
            )
            if fingerprint in seen:
                duplicates += 1
            seen.add(fingerprint)

            if caller := record.get("caller"):
                callers.add(caller)
            if callee := record.get("callee"):
                callees.add(callee)
            if timestamp := record.get("timestamp"):
                timestamps.append(timestamp)
            imei, imsi = record.get("imei"), record.get("imsi")
            if imei:
                imeis.add(imei)
                if imsi:
                    imei_to_imsi.setdefault(imei, set()).add(imsi)
            total_duration += int(record.get("duration_seconds") or 0)

        return {
            "record_count": len(records),
            "duplicate_record_count": duplicates,
            "distinct_caller_count": len(callers),
            "distinct_callee_count": len(callees),
            "distinct_imei_count": len(imeis),
            "imei_with_multiple_imsi_count": sum(
                1 for values in imei_to_imsi.values() if len(values) > 1
            ),
            "total_duration_seconds": total_duration,
            "first_timestamp": min(timestamps) if timestamps else None,
            "last_timestamp": max(timestamps) if timestamps else None,
        }
