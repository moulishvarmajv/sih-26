"""Authorized knowledge graph read.

Thin: resolve the authenticated context, ask GraphService, map to DTOs. The API
never touches Neo4j and never decides what a reader may see.

When the graph backend is down this returns GRAPH_UNAVAILABLE rather than
failing the whole application — only graph-specific operations depend on it.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, status

from app.api.dependencies import (
    get_case_repository,
    get_current_agency_context,
    get_current_user,
    get_graph_service,
)
from app.api.errors import AUTHENTICATED_ERRORS, GRAPH_ERRORS, ApiError, forbidden, http_error
from app.api.schemas import (
    GraphNodeDTO,
    GraphProvenanceDTO,
    GraphRelationshipDTO,
    GraphResponse,
)
from app.core.domain.agency import AgencyContext
from app.core.domain.identity import User
from app.core.graph.models import GraphNode, GraphRelationship
from app.core.graph.repository import GraphUnavailable
from app.core.graph.service import AuthorizedGraph, GraphAccessDenied, GraphService
from app.infrastructure.sqlite_case_repository import SQLiteCaseRepository

router = APIRouter(tags=["graph"])


@router.get(
    "/cases/{case_id}/graph",
    response_model=GraphResponse,
    responses={**AUTHENTICATED_ERRORS, **GRAPH_ERRORS},
)
def get_case_graph(
    case_id: str,
    user: User = Depends(get_current_user),
    context: AgencyContext | None = Depends(get_current_agency_context),
    cases: SQLiteCaseRepository = Depends(get_case_repository),
    service: GraphService = Depends(get_graph_service),
) -> GraphResponse:
    if context is None:
        raise forbidden(ApiError.NO_ACTIVE_CONTEXT)
    case = cases.get(case_id)
    if case is None:
        # Same code as an unauthorized case, so neither can be enumerated.
        raise forbidden(ApiError.CASE_ACCESS_DENIED)

    try:
        authorized = service.get_case_graph(user, context, case)
    except GraphAccessDenied:
        raise forbidden(ApiError.GRAPH_ACCESS_DENIED) from None
    except GraphUnavailable:
        raise http_error(
            ApiError.GRAPH_UNAVAILABLE, status.HTTP_503_SERVICE_UNAVAILABLE
        ) from None
    return _to_response(authorized)


def _to_response(authorized: AuthorizedGraph) -> GraphResponse:
    return GraphResponse(
        case_id=authorized.case_id,
        nodes=[_node_dto(node) for node in authorized.nodes],
        relationships=[_relationship_dto(rel) for rel in authorized.relationships],
        masked_properties=list(authorized.masked_properties),
        excluded_evidence_count=authorized.excluded_evidence_count,
    )


def _node_dto(node: GraphNode) -> GraphNodeDTO:
    return GraphNodeDTO(id=node.id, label=node.label.value, properties=dict(node.properties))


def _relationship_dto(relationship: GraphRelationship) -> GraphRelationshipDTO:
    provenance = relationship.provenance
    return GraphRelationshipDTO(
        id=relationship.observation_id,
        type=relationship.type.value,
        source=relationship.start.id,
        target=relationship.end.id,
        properties=dict(relationship.properties),
        provenance=None
        if provenance is None
        else GraphProvenanceDTO(
            evidence_id=provenance.evidence_id,
            evidence_version_id=provenance.evidence_version_id,
            source_type=provenance.source_type,
            observed_at=provenance.observed_at,
            trust_class=provenance.trust_class.value,
            processing_run_id=provenance.processing_run_id,
        ),
    )
