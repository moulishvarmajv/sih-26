"""Shared security fixtures: a real policy, engine, grant store and event store."""
import pytest

from app.core.domain.agency import Agency, AgencyContext
from app.core.domain.case import Case
from app.core.domain.identity import Clearance, Role, User
from app.core.evidence.models import EvidenceRecord, EvidenceState, TrustClassification
from app.infrastructure.sqlite_event_store import SQLiteEventStore
from app.security.authorization.policy_engine import ClearanceAuthorizationEngine
from app.security.grants import InMemoryAccessGrantRepository
from app.security.policy.loader import load_security_policy
from app.security.service import SecurityService

POLICE = Agency(id="POLICE", name="State Police", plugin_id="police")
FINANCIAL_CRIME = Agency(id="FINANCIAL_CRIME", name="Financial Crime Unit", plugin_id="financial_crime")

INVESTIGATOR = Role(
    id="ROLE-INVESTIGATOR",
    name="INVESTIGATOR",
    permissions=(
        "VIEW_CASE",
        "VIEW_EVIDENCE",
        "SWITCH_AGENCY_CONTEXT",
        "ANALYZE_EVIDENCE",
        "REANALYZE_EVIDENCE",
        "VIEW_GRAPH",
        "RUN_ENTITY_RESOLUTION",
        "VIEW_ENTITY_RESOLUTION",
        "REVIEW_ENTITY_RESOLUTION",
        "VIEW_ANALYTICS",
        "RUN_ANALYTICS",
        "VIEW_EVIDENCE_DEBT",
        "RECALCULATE_EVIDENCE_DEBT",
        "ACKNOWLEDGE_EVIDENCE_DEBT",
    ),
)
ANALYST = Role(
    id="ROLE-ANALYST",
    name="ANALYST",
    # No REANALYZE_EVIDENCE, no REVIEW_ENTITY_RESOLUTION and no debt
    # recalculation or acknowledgement: analysts read and analyse, they neither
    # reprocess evidence, rule on an identity claim, nor sign off a gap.
    permissions=(
        "VIEW_CASE",
        "VIEW_EVIDENCE",
        "SWITCH_AGENCY_CONTEXT",
        "ANALYZE_EVIDENCE",
        "VIEW_GRAPH",
        "RUN_ENTITY_RESOLUTION",
        "VIEW_ENTITY_RESOLUTION",
        "VIEW_ANALYTICS",
        "VIEW_EVIDENCE_DEBT",
    ),
)


@pytest.fixture
def policy():
    return load_security_policy()


@pytest.fixture
def engine(policy):
    return ClearanceAuthorizationEngine(policy)


@pytest.fixture
def grants():
    return InMemoryAccessGrantRepository()


@pytest.fixture
def event_store(tmp_path):
    store = SQLiteEventStore(tmp_path / "audit.db")
    yield store
    store.close()


@pytest.fixture
def security(engine, grants, event_store, policy):
    return SecurityService(
        engine=engine,
        grants=grants,
        event_store=event_store,
        clearance_policy=policy.clearance,
    )


def make_user(user_id="USR-104", level="L2", expires_at=None):
    return User(
        id=user_id,
        username=f"officer-{user_id.lower()}",
        roles=(INVESTIGATOR,),
        clearance=Clearance(
            level_code=level,
            granted_by="SP-OFFICE",
            granted_at="2026-01-01T00:00:00+00:00",
            expires_at=expires_at,
        ),
    )


def make_context(user_id="USR-104", level="L2", agency=POLICE, role=INVESTIGATOR):
    return AgencyContext(
        agency=agency,
        user_id=user_id,
        role=role,
        clearance=Clearance(
            level_code=level, granted_by="SP-OFFICE", granted_at="2026-01-01T00:00:00+00:00"
        ),
        department="INVESTIGATION",
        unit="CYBER-CELL",
    )


def make_case(case_id="CASE-001", agency_id="POLICE", security_level="L1"):
    return Case(
        id=case_id,
        agency_id=agency_id,
        title="Test case",
        status="OPEN",
        security_level=security_level,
    )


def make_evidence(
    evidence_id="EV-309", case_id="CASE-001", security_level="L2", sensitive_fields=()
):
    return EvidenceRecord(
        id=evidence_id,
        case_id=case_id,
        source_id="SRC-CDR",
        source_record_id="CDR-EXPORT-001",
        classification=TrustClassification.OBSERVED,
        state=EvidenceState.AVAILABLE,
        created_at="2026-02-01T00:00:00+00:00",
        security_level=security_level,
        sensitive_fields=sensitive_fields,
    )
