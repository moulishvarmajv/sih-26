"""Turns evidence payloads into entity observations.

The analogue of the graph mapper, and separated from it for the same reason: the
repository knows storage, the mapper knows what a CDR row means, and this knows
which entity a source is describing and under which canonical attributes.

Two rules this module holds to:

- It extracts an entity only where the source actually names one. A CDR row
  yields a Person observation only when the operator supplied a subscriber id;
  deriving a person from a phone number would be an inference dressed up as an
  observation.
- It canonicalises formatting and keeps the raw text alongside. `+91 98765
  43210` and `919876543210` compare equal because they are the same digits, not
  because anything decided they are the same person — that decision is scored,
  recorded and reviewable further down.

An extractor never scores, never merges and never writes.
"""
from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence

from app.core.evidence.models import EvidenceRecord, EvidenceVersion
from app.core.normalization import (
    NormalizationError,
    canonical_identifier,
    canonical_phone,
    comparable_address,
    comparable_name,
    normalized_text,
)
from app.core.resolution.models import EntityObservation, EntityType, observation_key

#: Canonical attribute names every extractor writes into. The scorer and the
#: policy refer to these names and to nothing source-specific, so a new source
#: needs an extractor but no change to matching.
ATTR_PHONE = "phone"
ATTR_IMEI = "imei"
ATTR_IMSI = "imsi"
ATTR_ACCOUNT = "account_number"
ATTR_NAME = "name"
ATTR_ADDRESS = "address"
ATTR_LOCALITY = "locality"
ATTR_NATIONAL_ID = "national_id_ref"
#: A stable identifier this source uses to point at an entity *another* source
#: owns — an operator subscriber id quoted by a register, for example. Matching
#: it is an exact-identifier signal, not a name guess.
ATTR_SOURCE_ENTITY_REF = "source_entity_ref"


class ObservationExtractor(Protocol):
    source_id: str

    def extract(
        self,
        record: EvidenceRecord,
        version: EvidenceVersion,
        payload: Mapping[str, Any],
    ) -> Sequence[EntityObservation]:
        """Return the entity observations this evidence version carries."""
        ...


class CdrObservationExtractor:
    """Person observations from a CDR export.

    One observation per subscriber the operator named, carrying the phone and
    handset it was seen on and the window it was observed in.
    """

    source_id = "SYNTHETIC_CDR"

    def extract(
        self,
        record: EvidenceRecord,
        version: EvidenceVersion,
        payload: Mapping[str, Any],
    ) -> list[EntityObservation]:
        rows = payload.get("records")
        if not isinstance(rows, list):
            return []

        by_subscriber: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            subscriber_id = str(row.get("subscriber_id", "")).strip()
            if not subscriber_id:
                continue  # no subscriber named: nothing observed to resolve
            bucket = by_subscriber.setdefault(
                subscriber_id, {"phones": {}, "imeis": {}, "imsis": {}, "timestamps": []}
            )
            _collect_phone(bucket, row.get("caller"))
            _collect_identifier(bucket, "imeis", row.get("imei"))
            _collect_identifier(bucket, "imsis", row.get("imsi"))
            timestamp = str(row.get("timestamp", "")).strip()
            if timestamp:
                bucket["timestamps"].append(timestamp)

        observations: list[EntityObservation] = []
        for subscriber_id, bucket in sorted(by_subscriber.items()):
            attributes, raw = {}, {}
            _single(attributes, raw, ATTR_PHONE, bucket["phones"])
            _single(attributes, raw, ATTR_IMEI, bucket["imeis"])
            _single(attributes, raw, ATTR_IMSI, bucket["imsis"])
            timestamps = sorted(bucket["timestamps"])
            observed_at = timestamps[0] if timestamps else version.ingested_at
            if timestamps:
                attributes["observed_from"] = timestamps[0]
                attributes["observed_to"] = timestamps[-1]
            observations.append(
                EntityObservation(
                    observation_id=observation_key(
                        EntityType.PERSON, subscriber_id, version.version_id
                    ),
                    case_id=record.case_id,
                    entity_type=EntityType.PERSON,
                    entity_key=subscriber_id,
                    source_id=record.source_id or self.source_id,
                    evidence_id=record.id,
                    evidence_version_id=version.version_id,
                    observed_at=observed_at,
                    attributes=attributes,
                    raw_attributes=raw,
                )
            )
        return observations


class SubscriberRegisterObservationExtractor:
    """Person observations from a subscriber register.

    A register row is already one entity, so extraction is a straight
    canonicalisation of the fields it carries.
    """

    source_id = "SYNTHETIC_SUBSCRIBER_REGISTER"

    def extract(
        self,
        record: EvidenceRecord,
        version: EvidenceVersion,
        payload: Mapping[str, Any],
    ) -> list[EntityObservation]:
        rows = payload.get("subscribers")
        if not isinstance(rows, list):
            return []

        observations: list[EntityObservation] = []
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            entity_key = str(row.get("register_id", "")).strip()
            if not entity_key:
                continue

            attributes: dict[str, str] = {}
            raw: dict[str, str] = {}
            _canonical(attributes, raw, ATTR_PHONE, row.get("msisdn"), canonical_phone)
            _canonical(attributes, raw, ATTR_IMEI, row.get("imei"), canonical_identifier)
            _canonical(
                attributes, raw, ATTR_ACCOUNT, row.get("account_number"), canonical_identifier
            )
            _canonical(
                attributes, raw, ATTR_NATIONAL_ID, row.get("national_id_ref"), canonical_identifier
            )
            _canonical(
                attributes,
                raw,
                ATTR_SOURCE_ENTITY_REF,
                row.get("operator_subscriber_id"),
                canonical_identifier,
            )
            _canonical(attributes, raw, ATTR_NAME, row.get("subscriber_name"), comparable_name)
            _canonical(
                attributes, raw, ATTR_ADDRESS, row.get("subscriber_address"), comparable_address
            )
            _canonical(attributes, raw, ATTR_LOCALITY, row.get("locality"), normalized_text)

            registered_at = str(row.get("registered_at", "")).strip() or version.ingested_at
            attributes["observed_from"] = registered_at
            attributes["observed_to"] = (
                str(row.get("valid_until", "")).strip() or registered_at
            )

            observations.append(
                EntityObservation(
                    observation_id=observation_key(
                        EntityType.PERSON, entity_key, version.version_id
                    ),
                    case_id=record.case_id,
                    entity_type=EntityType.PERSON,
                    entity_key=entity_key,
                    source_id=record.source_id or self.source_id,
                    evidence_id=record.id,
                    evidence_version_id=version.version_id,
                    observed_at=registered_at,
                    attributes=attributes,
                    raw_attributes=raw,
                )
            )
        return observations


def default_extractors() -> dict[str, ObservationExtractor]:
    """Extractors by source id. Evidence from an unmapped source is skipped, not guessed at."""
    return {
        CdrObservationExtractor.source_id: CdrObservationExtractor(),
        SubscriberRegisterObservationExtractor.source_id: (
            SubscriberRegisterObservationExtractor()
        ),
    }


def _collect_phone(bucket: dict[str, Any], value: Any) -> None:
    text = str(value or "").strip()
    if not text:
        return
    try:
        bucket["phones"].setdefault(canonical_phone(text), text)
    except NormalizationError:
        return  # unusable formatting is dropped rather than guessed at


def _collect_identifier(bucket: dict[str, Any], key: str, value: Any) -> None:
    text = str(value or "").strip()
    if not text:
        return
    try:
        bucket[key].setdefault(canonical_identifier(text), text)
    except NormalizationError:
        return


def _single(
    attributes: dict[str, str],
    raw: dict[str, str],
    attribute: str,
    observed: Mapping[str, str],
) -> None:
    """Record an attribute only when the evidence agreed on exactly one value.

    A subscriber seen on two handsets in one export has no single IMEI, and
    picking one would invent a fact. The attribute is simply absent, which the
    scorer treats as not comparable rather than as a disagreement.
    """
    if len(observed) != 1:
        return
    canonical, raw_value = next(iter(observed.items()))
    attributes[attribute] = canonical
    raw[attribute] = raw_value


def _canonical(
    attributes: dict[str, str],
    raw: dict[str, str],
    attribute: str,
    value: Any,
    canonicalise: Any,
) -> None:
    text = str(value or "").strip()
    if not text:
        return
    try:
        canonical = canonicalise(text)
    except NormalizationError:
        return
    if not canonical:
        return
    attributes[attribute] = canonical
    raw[attribute] = text
