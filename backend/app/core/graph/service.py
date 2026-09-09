"""Graph application service.

The only path between the API and the graph. Responsibilities kept here rather
than in the repository: authorization, case scoping, orchestration, mapping to
DTOs and audit.

Reading a case graph authorizes *per evidence item*, because the graph is a
projection of evidence: a reader who may not see one CDR must not see the calls
derived from it. Evidence that is denied is excluded from the query itself
rather than filtered afterwards, and evidence returned under a PARTIAL decision
has its identifiers masked before the response is built.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from app.core.audit.event_store import ActorType, EventDraft, EventStore, FlightRecorderEvent
from app.core.domain.agency import AgencyContext
from app.core.domain.case import Case
from app.core.domain.identity import User
from app.core.evidence.object_store import EvidenceObjectStore
from app.core.evidence.repository import EvidenceRepository
from app.core.graph.mapping import CdrGraphMapper, GraphMapper
from app.core.graph.models import GraphNode, GraphRelationship, GraphSnapshot, NodeLabel
from app.core.graph.repository import GraphRepository
from app.infrastructure.clock import utc_now_iso
from app.security.privacy.masking import mask_payload
from app.security.privacy.policy import PrivacyPolicy
from app.security.service import SecurityService

ACTION_VIEW_GRAPH = "VIEW_GRAPH"

#: Evidence field names carry into the graph under different property names.
#: A redaction on `caller` must therefore also redact `Phone.msisdn`, otherwise
#: the graph would hand back the number the evidence view masked.
EVIDENCE_FIELD_TO_GRAPH_PROPERTY: Mapping[str, tuple[str, ...]] = {
    "caller": ("msisdn", "raw_caller"),
    "callee": ("msisdn", "raw_callee"),
    "imei": ("imei",),
    "imsi": ("imsi",),
    "subscriber_name": ("person_id", "subscriber_name"),
}


class GraphAccessDenied(Exception):
    """Raised when authorization denies the graph. Carries no graph data."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class GraphIngestionSummary:
    case_id: str
    evidence_processed: int
    nodes_written: int
    relationships_written: int
    #: Evidence from a source with no registered mapper. Counted rather than
    #: guessed at or silently dropped: a source without a mapping has no graph
    #: projection yet, and pretending otherwise would invent structure.
    evidence_skipped: int = 0


@dataclass(frozen=True)
class AuthorizedGraph:
    """The subgraph one reader is allowed to see, already masked."""

    case_id: str
    nodes: tuple[GraphNode, ...]
    relationships: tuple[GraphRelationship, ...]
    masked_properties: tuple[str, ...]
    excluded_evidence_count: int


class GraphService:
    def __init__(
        self,
        graph_repository: GraphRepository,
        evidence_repository: EvidenceRepository,
        object_store: EvidenceObjectStore,
        security: SecurityService,
        event_store: EventStore,
        privacy: PrivacyPolicy,
        mappers: Mapping[str, GraphMapper] | None = None,
        clock: Callable[[], str] = utc_now_iso,
    ) -> None:
        self._graph = graph_repository
        self._evidence = evidence_repository
        self._objects = object_store
        self._security = security
        self._events = event_store
        self._privacy = privacy
        # Mappers are keyed by the source id that produced the evidence, so
        # adding a source does not mean touching this service.
        self._mappers: dict[str, GraphMapper] = (
            dict(mappers)
            if mappers is not None
            else {CdrGraphMapper.source_type: CdrGraphMapper()}
        )
        self._clock = clock

    # -- ingestion --------------------------------------------------------

    def ingest_case_evidence(
        self, case: Case, actor_id: str = "SYSTEM", correlation_id: str = "-"
    ) -> GraphIngestionSummary:
        """Project a case's evidence into the graph. Idempotent by construction."""
        records = self._evidence.list_evidence_for_case(case.id)
        self._record(
            FlightRecorderEvent.GRAPH_INGESTION_STARTED,
            actor_id,
            case.id,
            correlation_id,
            {"evidence_count": len(records)},
        )

        nodes_written = relationships_written = processed = skipped = 0
        try:
            self._graph.initialize_schema()
            for record in records:
                version = self._evidence.get_latest_version(record.id)
                if version is None:
                    continue
                mapper = self._mappers.get(record.source_id)
                if mapper is None:
                    skipped += 1
                    continue
                payload = json.loads(self._objects.get(version.payload_ref))
                snapshot = mapper.map(record, version, payload)
                nodes_written += self._graph.upsert_nodes(snapshot.nodes)
                relationships_written += self._graph.upsert_relationships(
                    snapshot.relationships
                )
                processed += 1
        except Exception as exc:
            self._record(
                FlightRecorderEvent.GRAPH_INGESTION_FAILED,
                actor_id,
                case.id,
                correlation_id,
                {"error_code": type(exc).__name__},
            )
            raise

        self._record(
            FlightRecorderEvent.GRAPH_INGESTION_COMPLETED,
            actor_id,
            case.id,
            correlation_id,
            {
                "evidence_processed": processed,
                "evidence_skipped": skipped,
                "nodes_written": nodes_written,
                "relationships_written": relationships_written,
            },
        )
        return GraphIngestionSummary(
            case.id, processed, nodes_written, relationships_written, skipped
        )

    # -- authorized read --------------------------------------------------

    def get_case_graph(
        self, user: User, context: AgencyContext, case: Case
    ) -> AuthorizedGraph:
        case_decision = self._security.authorize_case_access(
            user, context, case, ACTION_VIEW_GRAPH
        )
        if not case_decision.grants_access:
            self._record(
                FlightRecorderEvent.GRAPH_ACCESS_DENIED,
                user.id,
                case.id,
                case_decision.correlation_id,
                {"reason": case_decision.reason.value, "scope": "CASE"},
            )
            raise GraphAccessDenied(case_decision.reason.value)

        allowed_evidence: list[str] = []
        redacted_fields: set[str] = set()
        excluded = 0
        for record in self._evidence.list_evidence_for_case(case.id):
            decision = self._security.authorize_evidence_access(
                user, context, case, record, ACTION_VIEW_GRAPH
            )
            if not decision.grants_access:
                excluded += 1
                continue
            allowed_evidence.append(record.id)
            redacted_fields.update(decision.redacted_fields)

        if not allowed_evidence:
            self._record(
                FlightRecorderEvent.GRAPH_ACCESS_DENIED,
                user.id,
                case.id,
                case_decision.correlation_id,
                {"reason": "NO_AUTHORIZED_EVIDENCE", "scope": "EVIDENCE"},
            )
            raise GraphAccessDenied("NO_AUTHORIZED_EVIDENCE")

        snapshot = self._graph.fetch_case_graph(case.id, allowed_evidence)
        self._record(
            FlightRecorderEvent.GRAPH_QUERY_EXECUTED,
            user.id,
            case.id,
            case_decision.correlation_id,
            {
                "evidence_scope": len(allowed_evidence),
                "node_count": len(snapshot.nodes),
                "relationship_count": len(snapshot.relationships),
            },
        )

        masked_properties = self._graph_properties_for(redacted_fields)
        authorized = self._apply_masking(case.id, snapshot, masked_properties, excluded)
        self._record(
            FlightRecorderEvent.GRAPH_ACCESS_ALLOWED,
            user.id,
            case.id,
            case_decision.correlation_id,
            {
                "decision": case_decision.effect.value,
                "node_count": len(authorized.nodes),
                "relationship_count": len(authorized.relationships),
                "masked_properties": list(masked_properties),
                "excluded_evidence_count": excluded,
            },
        )
        return authorized

    def is_available(self) -> bool:
        return self._graph.is_available()

    # -- helpers ----------------------------------------------------------

    def _graph_properties_for(self, redacted_fields: set[str]) -> tuple[str, ...]:
        properties: set[str] = set()
        for field in redacted_fields:
            properties.update(EVIDENCE_FIELD_TO_GRAPH_PROPERTY.get(field, (field,)))
        return tuple(sorted(properties))

    def _apply_masking(
        self,
        case_id: str,
        snapshot: GraphSnapshot,
        masked_properties: tuple[str, ...],
        excluded: int,
    ) -> AuthorizedGraph:
        if not masked_properties:
            return AuthorizedGraph(case_id, snapshot.nodes, snapshot.relationships, (), excluded)

        partial = self._privacy.partial_mask_fields
        nodes = tuple(
            GraphNode(
                label=node.label,
                key=node.key,
                properties=mask_payload(node.properties, masked_properties, partial),
            )
            for node in snapshot.nodes
        )
        relationships = tuple(
            GraphRelationship(
                type=relationship.type,
                start=relationship.start,
                end=relationship.end,
                observation_id=relationship.observation_id,
                properties=mask_payload(relationship.properties, masked_properties, partial),
                provenance=relationship.provenance,
            )
            for relationship in snapshot.relationships
        )
        return AuthorizedGraph(case_id, nodes, relationships, masked_properties, excluded)

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


def node_display_label(node: GraphNode) -> str:
    """Human-facing label for a node, honouring whatever masking was applied."""
    key_property = {
        NodeLabel.PERSON: "person_id",
        NodeLabel.PHONE: "msisdn",
        NodeLabel.DEVICE: "imei",
        NodeLabel.CASE: "case_id",
        NodeLabel.EVIDENCE: "evidence_id",
    }.get(node.label)
    if key_property is None:
        return node.key
    return str(node.properties.get(key_property, node.key))
