"""Request/response shapes for the authentication boundary.

These are deliberately narrow projections: no password material, no policy
internals, no repository objects. Anything not listed here does not leave the
process.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class ClearanceResponse(BaseModel):
    level: str | None
    verified: bool
    expires_at: str | None = None


class AgencyResponse(BaseModel):
    agency_id: str
    name: str


class SessionResponse(BaseModel):
    session_id: str
    expires_at: str


class LoginResponse(BaseModel):
    token: str
    session: SessionResponse
    user_id: str
    display_name: str | None
    clearance: ClearanceResponse


class MeResponse(BaseModel):
    user_id: str
    username: str
    display_name: str | None
    roles: list[str]
    clearance: ClearanceResponse
    authorized_agencies: list[AgencyResponse]
    active_agency_id: str | None
    session: SessionResponse


class ContextSwitchRequest(BaseModel):
    agency_id: str = Field(min_length=1, max_length=64)
    department: str | None = Field(default=None, max_length=64)
    unit: str | None = Field(default=None, max_length=64)


class EvidenceSummary(BaseModel):
    evidence_id: str
    case_id: str
    source_id: str
    source_record_id: str
    classification: str
    state: str
    security_level: str | None
    created_at: str


class EvidenceListResponse(BaseModel):
    case_id: str
    evidence: list[EvidenceSummary]


class EvidenceVersionResponse(BaseModel):
    version_id: str
    version_number: int
    content_hash: str
    source_reference: str
    ingested_at: str
    state: str


class EvidenceVersionsResponse(BaseModel):
    evidence_id: str
    versions: list[EvidenceVersionResponse]


class EvidenceViewResponse(BaseModel):
    evidence: EvidenceSummary
    version: EvidenceVersionResponse
    payload: dict  # already masked server-side when the decision was PARTIAL
    decision: str
    masked_fields: list[str]


class AnalysisResultResponse(BaseModel):
    result_id: str
    run_id: str
    evidence_id: str
    evidence_version_id: str
    task_type: str
    classification: str
    state: str
    output_hash: str | None
    created_at: str
    reused: bool
    payload: dict | None


class GraphProvenanceDTO(BaseModel):
    evidence_id: str
    evidence_version_id: str
    source_type: str
    observed_at: str
    trust_class: str
    processing_run_id: str | None = None


class GraphNodeDTO(BaseModel):
    id: str  # opaque and stable; never the raw key, which may be masked
    label: str
    properties: dict


class GraphRelationshipDTO(BaseModel):
    id: str  # the observation id: deterministic, so re-ingestion does not change it
    type: str
    source: str
    target: str
    properties: dict
    provenance: GraphProvenanceDTO | None = None


class GraphResponse(BaseModel):
    case_id: str
    nodes: list[GraphNodeDTO]
    relationships: list[GraphRelationshipDTO]
    masked_properties: list[str]
    excluded_evidence_count: int


class ContextResponse(BaseModel):
    agency_id: str
    agency_name: str
    role: str
    clearance_level: str
    department: str | None = None
    unit: str | None = None
