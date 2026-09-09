"""Synthetic subscriber-register evidence source.

A second local dataset, no network. Where a CDR records calls, a register
records who a number was registered to — which is what makes entity resolution
demonstrable at all: a CDR alone carries no names or addresses to compare.

Like the CDR adapter it validates and refuses to guess, and it preserves what
the register wrote verbatim. Two entries for one household number stay two
entries; deciding whether they are one person is resolution's job, downstream,
with a score and a reviewable record.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from app.core.evidence.models import TrustClassification
from app.core.evidence.source import EvidenceSourceError, SourceEvidence

DEFAULT_DATASET = Path(__file__).with_name("synthetic_subscriber_sample.json")

SUBSCRIBER_SENSITIVE_FIELDS = (
    "subscriber_name",
    "subscriber_address",
    "account_number",
    "national_id_ref",
    "msisdn",
    "imei",
)
_REQUIRED_FIELDS = ("register_id", "subscriber_name", "msisdn")
_OPTIONAL_FIELDS = (
    "subscriber_address",
    "locality",
    "imei",
    "account_number",
    "national_id_ref",
    "operator_subscriber_id",
    "registered_at",
    "valid_until",
)


class SyntheticSubscriberRegisterSource:
    source_id = "SYNTHETIC_SUBSCRIBER_REGISTER"

    def __init__(
        self, dataset_path: str | Path = DEFAULT_DATASET, security_level: str = "L2"
    ) -> None:
        self._dataset_path = Path(dataset_path)
        self._security_level = security_level

    def fetch(self, case_id: str) -> Iterable[SourceEvidence]:
        document = self._load()
        registers = document.get("registers")
        if not isinstance(registers, list):
            raise EvidenceSourceError("dataset has no 'registers' list")

        emitted = []
        for register in registers:
            if not isinstance(register, Mapping):
                raise EvidenceSourceError("register entry is not an object")
            if register.get("case_id") != case_id:
                continue
            emitted.append(self._to_evidence(register, document))
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
        self, register: Mapping[str, Any], document: Mapping[str, Any]
    ) -> SourceEvidence:
        register_id = register.get("register_id")
        if not isinstance(register_id, str) or not register_id:
            raise EvidenceSourceError("register is missing 'register_id'")

        subscribers = register.get("subscribers")
        if not isinstance(subscribers, list) or not subscribers:
            raise EvidenceSourceError(f"register '{register_id}' has no subscribers")

        normalised = [
            normalise_subscriber(entry, register_id, index)
            for index, entry in enumerate(subscribers)
        ]

        return SourceEvidence(
            source_record_id=register_id,
            payload={
                "register_id": register_id,
                "registrar": register.get("registrar"),
                "subscriber_count": len(normalised),
                "subscribers": normalised,
            },
            classification=TrustClassification.OBSERVED,
            source_reference=f"{document.get('dataset', 'unknown')}:{register_id}",
            security_level=self._security_level,
            sensitive_fields=SUBSCRIBER_SENSITIVE_FIELDS,
        )


def normalise_subscriber(entry: Any, register_id: str, index: int) -> dict[str, Any]:
    """Validate one register row and return it in canonical field order.

    Formatting is preserved: rewriting `+91 98765 43210` into digits here would
    discard how the register actually recorded it, and that raw form is the
    provenance a canonical key is derived from later.
    """
    where = f"{register_id}[{index}]"
    if not isinstance(entry, Mapping):
        raise EvidenceSourceError(f"{where}: subscriber is not an object")

    for field in _REQUIRED_FIELDS:
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            raise EvidenceSourceError(f"{where}: missing or invalid '{field}'")

    normalised = {field: entry[field] for field in _REQUIRED_FIELDS}
    for field in _OPTIONAL_FIELDS:
        if field in entry:
            value = entry[field]
            if not isinstance(value, str):
                raise EvidenceSourceError(f"{where}: '{field}' must be a string")
            normalised[field] = value
    return normalised
