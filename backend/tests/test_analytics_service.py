"""Analytics over the synthetic case, and the boundary it must not cross.

CASE-003 is shaped so each structure the phase claims to detect is present and
unambiguous:

    group A / group B      joined only through one phone, in the open evidence
    the helpline           four unrelated callers, high degree, nothing else
    a zero-second call     a connection that is structurally real and thin
    eight calls in an hour against otherwise spread-out contact
    a restricted export    one phone that appears nowhere else

The last one carries the phase's mandatory security property, and it is checked
from both directions: the cleared reader sees the entity, and the uncleared one
finds no trace of it anywhere in any result.
"""
import pytest

from app.core.analytics.models import SignalReason, SignalStatus, SignalType
from app.core.analytics.policy import load_analytics_policy
from app.core.analytics.service import (
    AnalyticsAccessDenied,
    AnalyticsEntityNotFound,
    GraphAnalyticsService,
    SignalNotFound,
)
from app.core.audit.event_store import FlightRecorderEvent
from app.core.domain.case import Case
from app.core.evidence.service import EvidenceService
from app.core.graph.models import NodeLabel, node_ref_id
from app.core.graph.service import GraphService
from app.infrastructure.local_object_store import LocalFileEvidenceObjectStore
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from app.infrastructure.sqlite_analytics_repository import SQLiteAnalyticsRepository
from app.infrastructure.sqlite_evidence_repository import SQLiteEvidenceRepository
from tests.conftest import ANALYST, make_context, make_user
from tests.graph_fakes import InMemoryGraphRepository

CASE = Case(
    id="CASE-003", agency_id="POLICE", title="Analytics case", status="OPEN", security_level="L1"
)
OTHER_CASE = Case(
    id="CASE-001", agency_id="POLICE", title="Other case", status="OPEN", security_level="L1"
)
READER = "USR-104"

# The fixture's identifiers, as canonical graph keys.
GROUP_A = ("919820100001", "919820100002", "919820100003")
GROUP_B = ("919730200001", "919730200002", "919730200003")
BRIDGE = "919810300001"
HELPLINE = "911800111222"
STRAY = "919999400001"
RESTRICTED = "919000500001"


def phone(msisdn: str) -> str:
    """The hashed entity id analytics uses for a phone."""
    return node_ref_id(NodeLabel.PHONE, msisdn)


@pytest.fixture
def wiring(tmp_path, security, grants, policy, event_store):
    evidence_repo = SQLiteEvidenceRepository(tmp_path / "investigation.db")
    analytics_repo = SQLiteAnalyticsRepository(tmp_path / "investigation.db")
    objects = LocalFileEvidenceObjectStore(tmp_path / "objects")
    graph = InMemoryGraphRepository()

    evidence = EvidenceService(evidence_repo, objects, security, event_store, policy.privacy)
    graphs = GraphService(graph, evidence_repo, objects, security, event_store, policy.privacy)
    analytics = GraphAnalyticsService(
        graph_service=graphs,
        graph_repository=graph,
        analytics_repository=analytics_repo,
        event_store=event_store,
        policy=load_analytics_policy(),
    )

    grants.grant_agency(READER, "POLICE")
    for case in (CASE, OTHER_CASE):
        grants.grant_case(READER, "POLICE", case.id, need_to_know=True)
        evidence.ingest_from_source(case, SyntheticCDRSource())
        graphs.ingest_case_evidence(case)

    yield {
        "analytics": analytics,
        "graphs": graphs,
        "graph": graph,
        "evidence_repo": evidence_repo,
        "analytics_repo": analytics_repo,
    }
    evidence_repo.close()
    analytics_repo.close()


@pytest.fixture
def analytics(wiring):
    return wiring["analytics"]


def reader(level="L2"):
    return make_user(READER, level=level), make_context(READER, level=level)


def overview(analytics, level="L2", case=CASE):
    user, context = reader(level)
    return analytics.overview(user, context, case)


# -- structure ---------------------------------------------------------------


def test_the_case_divides_into_the_groups_the_data_describes(analytics):
    """Group A/B with the bridge, and the helpline's callers, are separate."""
    components = overview(analytics).components

    assert len(components) == 2
    assert components[0].entity_count > components[1].entity_count
    assert components[0].dominant_entity_type == "Phone"


def test_degree_is_measured_and_ranked_within_the_case(analytics):
    top = overview(analytics).top_connectivity

    assert top[0].rank == 1
    assert top[0].degree >= top[-1].degree
    assert all(metric.rank_of == overview(analytics).entity_count for metric in top)


def test_a_busy_helpline_is_reported_as_connectivity_not_as_conduct(analytics):
    """The helpline is high degree for a mundane reason, and nothing implies otherwise."""
    measured = {m.entity.entity_id: m for m in overview(analytics, "L3").top_connectivity}

    helpline = measured[phone(HELPLINE)]
    assert helpline.degree >= 4
    assert helpline.entity_types_touched


def test_the_only_link_between_the_two_groups_is_found(analytics):
    """At L2 the restricted export is out of scope, so the bridge is the sole route."""
    found = {b.entity.entity_id: b for b in overview(analytics).bridges}

    bridge = found[phone(BRIDGE)]
    assert bridge.groups_separated >= 2
    assert bridge.separated_side_size >= 2
    assert bridge.rests_on_weak_relationship is False


def test_the_bridge_outranks_entities_that_merely_hold_a_leaf(analytics):
    """A3 separates only the stray number; the bridge separates two groups."""
    ranked = [metric.entity.entity_id for metric in overview(analytics).bridges]

    assert phone(BRIDGE) in ranked and phone(GROUP_A[2]) in ranked
    assert ranked.index(phone(BRIDGE)) < ranked.index(phone(GROUP_A[2]))


def test_a_single_zero_second_call_is_marked_as_a_thin_connection(analytics):
    """Structure alone does not establish that two groups are connected.

    A3 is an articulation point only because one zero-second call to a number
    seen nowhere else hangs off it. The signal reports the separation and says
    what it rests on.
    """
    found = {b.entity.entity_id: b for b in overview(analytics).bridges}

    holder = found[phone(GROUP_A[2])]
    assert holder.rests_on_weak_relationship is True
    assert holder.separated_side_size == 1
    assert not found[phone(BRIDGE)].rests_on_weak_relationship


def test_the_concentrated_hour_is_detected(analytics):
    concentrations = overview(analytics).concentrations

    assert len(concentrations) == 1
    assert concentrations[0].event_count == 8
    assert concentrations[0].concentration_ratio > 2.0
    assert concentrations[0].supporting_evidence_ids


def test_analytics_are_repeatable(analytics):
    """The same authorized graph always yields the same answer."""
    first, second = overview(analytics), overview(analytics)

    assert [c.component_id for c in first.components] == [
        c.component_id for c in second.components
    ]
    assert [m.entity.entity_id for m in first.top_connectivity] == [
        m.entity.entity_id for m in second.top_connectivity
    ]
    assert [b.entity.entity_id for b in first.bridges] == [
        b.entity.entity_id for b in second.bridges
    ]


def test_provenance_scaffolding_is_not_treated_as_connection(analytics):
    """Two phones are not connected because they appeared in the same export."""
    types = {m.entity.entity_type for m in overview(analytics).top_connectivity}

    assert "Evidence" not in types
    assert "Case" not in types


# -- entity and path ---------------------------------------------------------


def test_entity_analytics_describe_the_shape_around_one_entity(analytics):
    user, context = reader()

    result = analytics.entity_analytics(user, context, CASE, phone(BRIDGE))

    assert result.entity.entity_id == phone(BRIDGE)
    assert result.connectivity.degree > 0
    assert result.bridge is not None
    assert result.component_id is not None
    assert result.neighbours


def test_a_path_between_the_two_groups_runs_through_the_bridge(analytics):
    user, context = reader()

    path = analytics.shortest_path(user, context, CASE, phone(GROUP_A[0]), phone(GROUP_B[0]))

    assert path.found is True
    assert path.reason is SignalReason.PATH_FOUND
    assert 0 < path.length <= path.max_length_searched
    assert phone(BRIDGE) in {entity.entity_id for entity in path.entities}
    assert path.evidence_ids


def test_a_path_that_does_not_exist_is_reported_as_absent(analytics):
    """The helpline's callers are in a separate component."""
    user, context = reader()

    path = analytics.shortest_path(user, context, CASE, phone(GROUP_A[0]), phone(HELPLINE))

    assert path.found is False
    assert path.steps == ()
    assert path.reason is SignalReason.NO_PATH_WITHIN_LIMIT


def test_a_path_is_bounded_by_policy(analytics):
    user, context = reader()

    path = analytics.shortest_path(user, context, CASE, phone(GROUP_A[0]), phone(GROUP_B[0]))

    assert path.max_length_searched == load_analytics_policy().limits.max_path_length


def test_an_unknown_entity_is_not_found(analytics):
    user, context = reader()

    with pytest.raises(AnalyticsEntityNotFound):
        analytics.entity_analytics(user, context, CASE, "phone:doesnotexist")


# -- restricted evidence: the mandatory security property --------------------


def test_a_cleared_reader_sees_the_restricted_entity(analytics):
    """Establishes that the entity exists, so its absence below means something."""
    entities = {m.entity.entity_id for m in overview(analytics, "L3").top_connectivity}
    all_entities = {
        member.entity_id
        for component in overview(analytics, "L3").components
        for member in component.members
    }

    assert phone(RESTRICTED) in all_entities
    assert overview(analytics, "L3").excluded_evidence_count == 0


def test_an_uncleared_reader_sees_no_trace_of_the_restricted_entity(analytics):
    """The mandatory check: B must not appear anywhere, in any form."""
    result = overview(analytics, "L2")

    members = {
        member.entity_id for component in result.components for member in component.members
    }
    connectivity = {metric.entity.entity_id for metric in result.top_connectivity}
    bridges = {metric.entity.entity_id for metric in result.bridges}

    assert phone(RESTRICTED) not in members
    assert phone(RESTRICTED) not in connectivity
    assert phone(RESTRICTED) not in bridges
    assert result.excluded_evidence_count == 1


def test_no_result_carries_the_restricted_identifier_as_text(analytics):
    """Not merely absent as an id — absent as a value, anywhere in the payload."""
    result = overview(analytics, "L2")

    assert RESTRICTED not in str(result)
    assert "919000500001" not in str(result)


def test_a_restricted_entity_cannot_be_reached_by_asking_for_it(analytics):
    user, context = reader("L2")

    with pytest.raises(AnalyticsEntityNotFound):
        analytics.entity_analytics(user, context, CASE, phone(RESTRICTED))


def test_a_path_cannot_be_routed_through_a_restricted_entity(analytics):
    """The restricted export links A to B directly; an L2 reader must not use it."""
    user, context = reader("L2")

    with pytest.raises(AnalyticsEntityNotFound):
        analytics.shortest_path(user, context, CASE, phone(GROUP_A[0]), phone(RESTRICTED))


def test_analytics_are_computed_over_the_authorized_graph_only(analytics):
    """A narrower reader legitimately gets a smaller graph, not a filtered one."""
    cleared, restricted = overview(analytics, "L3"), overview(analytics, "L2")

    assert cleared.entity_count > restricted.entity_count
    assert cleared.relationship_count > restricted.relationship_count
    assert restricted.excluded_evidence_count == 1


def test_identifiers_are_masked_for_a_partial_reader(analytics):
    result = overview(analytics, "L2")

    assert "msisdn" in result.masked_properties
    labels = {metric.entity.label for metric in result.top_connectivity}
    assert all(not label.isdigit() for label in labels)


def test_a_cleared_reader_sees_unmasked_labels(analytics):
    result = overview(analytics, "L3")

    assert result.masked_properties == ()
    assert any(metric.entity.label.isdigit() for metric in result.top_connectivity)


# -- authorization -----------------------------------------------------------


def test_a_reader_without_the_case_is_denied(analytics, grants):
    grants.revoke_case(READER, "POLICE", CASE.id)
    user, context = reader()

    with pytest.raises(AnalyticsAccessDenied):
        analytics.overview(user, context, CASE)


def test_a_denial_carries_no_graph_data(analytics, grants):
    grants.revoke_case(READER, "POLICE", CASE.id)
    user, context = reader()

    with pytest.raises(AnalyticsAccessDenied) as denied:
        analytics.overview(user, context, CASE)

    assert "9198" not in str(denied.value)
    assert "9197" not in str(denied.value)


def test_a_role_without_the_run_permission_cannot_run_analytics(analytics):
    """The analyst role may read analytics but not record signals."""
    user = make_user(READER)
    context = make_context(READER, role=ANALYST)

    with pytest.raises(AnalyticsAccessDenied):
        analytics.run(user, context, CASE)


def test_a_role_without_the_run_permission_may_still_read(analytics):
    user = make_user(READER)
    context = make_context(READER, role=ANALYST)

    assert analytics.overview(user, context, CASE).entity_count > 0


def test_signals_are_scoped_to_their_case(analytics):
    user, context = reader()
    analytics.run(user, context, CASE)
    analytics.run(user, context, OTHER_CASE)

    here = analytics.list_signals(user, context, CASE)
    there = analytics.list_signals(user, context, OTHER_CASE)

    assert here and there
    assert {signal.case_id for signal in here} == {CASE.id}
    assert {signal.case_id for signal in there} == {OTHER_CASE.id}


def test_a_signal_cannot_be_read_through_the_wrong_case(analytics):
    user, context = reader()
    analytics.run(user, context, CASE)
    signal = analytics.list_signals(user, context, CASE)[0]

    with pytest.raises(SignalNotFound):
        analytics.get_signal(user, context, OTHER_CASE, signal.signal_id)


# -- runs, signals and history -----------------------------------------------


def test_a_run_records_its_scope_and_version(analytics, wiring):
    user, context = reader()

    run = analytics.run(user, context, CASE)

    assert run.analytics_version == load_analytics_policy().analytics_version
    assert run.evidence_ids
    assert run.signal_count > 0
    assert run.executed_by == READER
    assert wiring["analytics_repo"].get_run(run.run_id) == run


def test_signals_explain_themselves(analytics):
    user, context = reader()
    analytics.run(user, context, CASE)

    for signal in analytics.list_signals(user, context, CASE):
        assert signal.reasons
        assert signal.analytics_version
        assert signal.supporting_evidence_ids or signal.signal_type is (
            SignalType.COMPONENT_STRUCTURE
        )
        if signal.metrics:
            total = sum(metric.contribution for metric in signal.metrics)
            assert abs(min(1.0, total) - signal.score) < 1e-6


def test_every_score_exposes_its_inputs_and_weights(analytics):
    user, context = reader()
    analytics.run(user, context, CASE)

    ranked = [
        signal
        for signal in analytics.list_signals(user, context, CASE)
        if signal.signal_type is SignalType.CROSS_DOMAIN_BRIDGE
    ]

    assert ranked
    for metric in ranked[0].metrics:
        assert metric.weight > 0
        assert 0.0 <= metric.normalized <= 1.0
        assert abs(metric.contribution - metric.normalized * metric.weight) < 1e-6


def test_the_expected_signal_types_are_produced(analytics):
    user, context = reader()
    analytics.run(user, context, CASE)

    produced = {signal.signal_type for signal in analytics.list_signals(user, context, CASE)}

    assert SignalType.HIGH_CONNECTIVITY in produced
    assert SignalType.CROSS_DOMAIN_BRIDGE in produced
    assert SignalType.COMPONENT_STRUCTURE in produced
    assert SignalType.TEMPORAL_CONCENTRATION in produced


def test_a_weak_connection_is_reported_with_its_caveat(analytics):
    user, context = reader()
    analytics.run(user, context, CASE)

    flagged = [
        signal
        for signal in analytics.list_signals(user, context, CASE)
        if SignalReason.RESTS_ON_SINGLE_WEAK_RELATIONSHIP in signal.reasons
    ]

    assert flagged
    assert flagged[0].detail["rests_on_weak_relationship"] is True


def test_re_running_supersedes_rather_than_duplicates(analytics, wiring):
    user, context = reader()
    first = analytics.run(user, context, CASE)
    signal_id = analytics.list_signals(user, context, CASE)[0].signal_id

    second = analytics.run(user, context, CASE)

    active = analytics.list_signals(user, context, CASE)
    assert len({signal.signal_id for signal in active}) == len(active)
    history = wiring["analytics_repo"].list_signal_history(signal_id)
    assert len(history) == 2
    assert history[0].status is SignalStatus.SUPERSEDED
    assert history[1].status is SignalStatus.ACTIVE
    assert history[1].version == 2
    assert first.run_id != second.run_id or first.executed_at == second.executed_at


def test_history_preserves_what_an_earlier_run_concluded(analytics, wiring):
    user, context = reader()
    analytics.run(user, context, CASE)
    signal_id = analytics.list_signals(user, context, CASE)[0].signal_id
    original = wiring["analytics_repo"].get_signal(signal_id)

    analytics.run(user, context, CASE)

    history = wiring["analytics_repo"].list_signal_history(signal_id)
    assert history[0].score == original.score
    assert history[0].analytics_version == original.analytics_version


def test_reading_signals_computes_nothing(analytics, wiring):
    user, context = reader()

    assert analytics.list_signals(user, context, CASE) == []
    assert wiring["analytics_repo"].list_runs(CASE.id) == []


def test_an_overview_persists_nothing(analytics, wiring):
    user, context = reader()

    analytics.overview(user, context, CASE)

    assert wiring["analytics_repo"].list_runs(CASE.id) == []
    assert analytics.list_signals(user, context, CASE) == []


# -- audit -------------------------------------------------------------------


def test_a_run_is_audited_end_to_end(analytics, event_store):
    user, context = reader()

    analytics.run(user, context, CASE)

    def of(event_type):
        return [
            event for event in event_store.list_by_type(event_type) if event.case_id == CASE.id
        ]

    assert len(of(FlightRecorderEvent.ANALYTICS_STARTED)) == 1
    assert of(FlightRecorderEvent.ANALYTICS_COMPLETED)
    assert of(FlightRecorderEvent.SIGNAL_CREATED)


def test_a_second_run_records_revisions_not_creations(analytics, event_store):
    user, context = reader()
    analytics.run(user, context, CASE)
    created = len(event_store.list_by_type(FlightRecorderEvent.SIGNAL_CREATED))

    analytics.run(user, context, CASE)

    assert len(event_store.list_by_type(FlightRecorderEvent.SIGNAL_CREATED)) == created
    assert event_store.list_by_type(FlightRecorderEvent.SIGNAL_REVISED)


def test_audit_payloads_explain_without_the_data(analytics, event_store):
    user, context = reader()

    analytics.run(user, context, CASE)

    signal_events = event_store.list_by_type(FlightRecorderEvent.SIGNAL_CREATED)
    payload = dict(signal_events[0].payload)
    assert payload["analytics_version"]
    assert payload["reasons"]
    assert "919820100001" not in str(payload)


def test_a_denied_analytics_call_is_audited(analytics, event_store, grants):
    grants.revoke_case(READER, "POLICE", CASE.id)
    user, context = reader()

    with pytest.raises(AnalyticsAccessDenied):
        analytics.overview(user, context, CASE)

    denied = event_store.list_by_type(FlightRecorderEvent.ANALYTICS_ACCESS_DENIED)
    assert denied
    assert denied[0].case_id == CASE.id
