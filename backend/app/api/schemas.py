"""Request/response shapes for the authentication boundary.

These are deliberately narrow projections: no password material, no policy
internals, no repository objects. Anything not listed here does not leave the
process.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """The body of every error response: a stable code and nothing else."""

    error: str


class ErrorResponse(BaseModel):
    detail: ErrorDetail


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

class MatchEvidenceDTO(BaseModel):
    signal: str
    attribute: str  # a field name; a signal never reports the value it compared
    outcome: str
    weight: float
    contribution: float
    similarity: float | None = None


class ResolutionConflictDTO(BaseModel):
    attribute: str
    rule: str
    penalty: float
    blocks_auto_accept: bool
    similarity: float | None = None


class MatchExplanationDTO(BaseModel):
    """Why a resolution came out the way it did, in machine-readable form."""

    recommendation: str
    score: float
    evidence_weight: float  # how much was comparable, not how well it agreed
    confidence: str
    confidence_floor: float  # the band's lower bound, so the band is never a bare label
    policy_version: str
    reasons: list[str]
    evidence: list[MatchEvidenceDTO]
    conflicts: list[ResolutionConflictDTO]


class ResolvedEntityDTO(BaseModel):
    entity_ref: str  # opaque and stable; never the raw key, which may be masked
    entity_type: str
    label: str  # masked when the reader's evidence decision was PARTIAL
    source_id: str
    evidence_id: str
    evidence_version_id: str
    observed_at: str


class ResolutionReviewDTO(BaseModel):
    reviewer_id: str
    action: str
    reviewed_at: str
    reason: str | None = None


class CandidateOriginDTO(BaseModel):
    """Why the pair was ever compared."""

    candidate_id: str
    blocking_strategy: str
    blocking_key_attribute: str
    created_at: str


class EntityResolutionResponse(BaseModel):
    resolution_id: str
    lineage_id: str
    resolution_version: int
    case_id: str
    entity_type: str
    status: str
    left: ResolvedEntityDTO
    right: ResolvedEntityDTO
    explanation: MatchExplanationDTO
    policy_version: str
    created_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    decision_actor: str | None = None  # SYSTEM or HUMAN, never conflated
    decision_reason: str | None = None
    superseded_by: str | None = None
    trust_class: str  # always INFERRED: a resolution is never an observation
    candidate: CandidateOriginDTO | None = None
    reviews: list[ResolutionReviewDTO] = []
    masked_fields: list[str] = []


class EntityResolutionListResponse(BaseModel):
    case_id: str
    resolutions: list[EntityResolutionResponse]


class ResolutionRunResponse(BaseModel):
    case_id: str
    policy_version: str
    evidence_considered: int
    evidence_excluded: int
    observations: int
    candidates: int
    auto_accepted: int
    review_required: int
    unresolved: int
    superseded: int
    unchanged: int
    links_projected: int
    graph_available: bool


class ResolutionReviewRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=512)


class AnalyticsEntityDTO(BaseModel):
    entity_id: str  # opaque and stable; never the natural key, which may be masked
    entity_type: str
    label: str  # masked when the reader's evidence decision was PARTIAL


class SignalMetricDTO(BaseModel):
    name: str
    value: float
    normalized: float  # the value mapped into [0, 1] by the policy's saturation point
    weight: float
    contribution: float  # normalized * weight: what actually moved the score


class ConnectivityDTO(BaseModel):
    """Degree within the *authorized* case graph, not the whole graph."""

    entity: AnalyticsEntityDTO
    degree: int
    in_degree: int
    out_degree: int
    distinct_neighbours: int
    entity_types_touched: list[str]
    rank: int
    rank_of: int
    supporting_relationship_ids: list[str]
    supporting_evidence_ids: list[str]


class BridgeDTO(BaseModel):
    entity: AnalyticsEntityDTO
    groups_separated: int
    group_sizes: list[int]
    separated_side_size: int
    entity_types_spanned: list[str]
    neighbour_count: int
    rests_on_weak_relationship: bool
    supporting_relationship_ids: list[str]
    supporting_evidence_ids: list[str]


class ComponentDTO(BaseModel):
    component_id: str
    entity_count: int
    relationship_count: int
    entity_type_counts: dict
    dominant_entity_type: str
    members: list[AnalyticsEntityDTO]
    supporting_evidence_ids: list[str]


class TemporalWindowDTO(BaseModel):
    window_start: str
    window_end: str
    event_count: int
    mean_event_count: float
    concentration_ratio: float
    supporting_relationship_ids: list[str]
    supporting_evidence_ids: list[str]


class AnalyticsOverviewResponse(BaseModel):
    case_id: str
    analytics_version: str
    entity_count: int
    relationship_count: int
    evidence_in_scope: int
    excluded_evidence_count: int
    truncated: bool
    masked_properties: list[str]
    components: list[ComponentDTO]
    top_connectivity: list[ConnectivityDTO]
    bridges: list[BridgeDTO]
    temporal_concentrations: list[TemporalWindowDTO]


class EntityAnalyticsResponse(BaseModel):
    case_id: str
    analytics_version: str
    entity: AnalyticsEntityDTO
    connectivity: ConnectivityDTO
    bridge: BridgeDTO | None = None
    component_id: str | None = None
    component_entity_count: int
    neighbours: list[AnalyticsEntityDTO]
    masked_properties: list[str]


class PathStepDTO(BaseModel):
    relationship_id: str
    relationship_type: str
    from_entity: AnalyticsEntityDTO
    to_entity: AnalyticsEntityDTO
    evidence_id: str
    observed_at: str


class PathResponse(BaseModel):
    case_id: str
    analytics_version: str
    source: AnalyticsEntityDTO
    target: AnalyticsEntityDTO
    found: bool
    length: int
    max_length_searched: int
    reason: str
    steps: list[PathStepDTO]
    entities: list[AnalyticsEntityDTO]
    supporting_evidence_ids: list[str]


class SignalResponse(BaseModel):
    signal_id: str
    case_id: str
    signal_type: str
    status: str
    version: int
    score: float
    confidence: str
    reasons: list[str]
    metrics: list[SignalMetricDTO]
    entities: list[AnalyticsEntityDTO]
    supporting_relationship_ids: list[str]
    supporting_evidence_ids: list[str]
    detail: dict
    created_at: str
    analytics_version: str
    run_id: str


class SignalListResponse(BaseModel):
    case_id: str
    signals: list[SignalResponse]


class AnalyticsRunResponse(BaseModel):
    run_id: str
    case_id: str
    analytics_version: str
    executed_at: str
    executed_by: str
    evidence_in_scope: int
    node_count: int
    relationship_count: int
    signal_count: int
    excluded_evidence_count: int
    truncated: bool
