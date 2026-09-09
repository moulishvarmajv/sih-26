"""Deterministic graph metrics, checked against graphs whose answers are known.

These build views by hand rather than going through evidence, so a metric can be
pinned down without a database, a case or a reader. Behaviour over the synthetic
dataset is covered in `test_analytics_service.py`.
"""
import pytest

from app.core.analytics.graph_view import AnalysableGraph, ViewRelationship
from app.core.analytics.metrics import (
    articulation_points,
    bridges,
    components,
    concentrated_windows,
    connectivity,
    separated_regions,
    temporal_windows,
)
from app.core.analytics.models import AnalyticsEntity, SignalReason, SignalType
from app.core.analytics.policy import (
    AnalyticsPolicy,
    AnalyticsPolicyError,
    load_analytics_policy,
)


@pytest.fixture
def policy():
    return load_analytics_policy()


def entity(name, entity_type="Phone"):
    return AnalyticsEntity(entity_id=name, entity_type=entity_type, label=name)


def relationship(source, target, index, event_at=None, duration=None, kind="CALLED"):
    return ViewRelationship(
        relationship_id=f"REL-{index:03d}",
        type=kind,
        source_id=source,
        target_id=target,
        evidence_id="EV-1",
        evidence_version_id="EV-1-v1",
        observed_at="2026-03-01T00:00:00+00:00",
        event_at=event_at,
        duration_seconds=0 if duration is None else duration,
        duration_measured=duration is not None,
        trust_class="OBSERVED",
    )


def graph(edges, types=None, extra_entities=()):
    """A view built from (source, target) or (source, target, kwargs) tuples."""
    types = types or {}
    relationships = []
    for index, edge in enumerate(edges):
        source, target = edge[0], edge[1]
        options = edge[2] if len(edge) > 2 else {}
        relationships.append(relationship(source, target, index, **options))
    relationships = tuple(relationships)
    names = {name for edge in edges for name in edge[:2]} | set(extra_entities)
    entities = {name: entity(name, types.get(name, "Phone")) for name in sorted(names)}
    adjacency = {name: set() for name in entities}
    for item in relationships:
        if item.source_id != item.target_id:
            adjacency[item.source_id].add(item.target_id)
            adjacency[item.target_id].add(item.source_id)
    return AnalysableGraph(
        case_id="CASE-T",
        entities=entities,
        relationships=relationships,
        evidence_ids=("EV-1",),
        masked_properties=(),
        excluded_evidence_count=0,
        adjacency={key: frozenset(value) for key, value in adjacency.items()},
    )


# -- articulation points -----------------------------------------------------


@pytest.mark.parametrize(
    "edges,expected",
    [
        ([("A", "B"), ("B", "C")], {"B"}),
        ([("A", "B"), ("B", "C"), ("C", "A")], set()),
        ([("C", "A"), ("C", "B"), ("C", "D")], {"C"}),
        ([("A", "B"), ("B", "X"), ("X", "A"), ("X", "C"), ("C", "D"), ("D", "X")], {"X"}),
        ([("A", "B"), ("B", "C"), ("C", "A"), ("C", "D"), ("D", "E"), ("E", "C")], {"C"}),
        ([("A", "B"), ("C", "D")], set()),
        ([("A", "B"), ("B", "C"), ("C", "D"), ("D", "E")], {"B", "C", "D"}),
    ],
    ids=["path", "triangle", "star", "two-triangles", "bowtie", "disconnected", "chain"],
)
def test_articulation_points_match_hand_worked_graphs(edges, expected):
    assert articulation_points(graph(edges).adjacency) == expected


def test_a_lone_entity_separates_nothing():
    assert articulation_points(graph([], extra_entities=["A"]).adjacency) == set()


def test_articulation_points_do_not_depend_on_input_order():
    forward = [("A", "B"), ("B", "C"), ("C", "D"), ("D", "E")]
    assert articulation_points(graph(forward).adjacency) == articulation_points(
        graph(list(reversed(forward))).adjacency
    )


def test_separated_regions_report_whole_groups_not_neighbours():
    """The finding is what gets cut off, not how many neighbours there were."""
    edges = [("A1", "A2"), ("A2", "A3"), ("BR", "A1"), ("BR", "B1"), ("B1", "B2")]

    regions = separated_regions(graph(edges).adjacency, "BR")

    assert [sorted(region) for region in regions] == [["A1", "A2", "A3"], ["B1", "B2"]]


# -- connectivity ------------------------------------------------------------


def test_degree_counts_relationships_and_direction(policy):
    view = graph([("A", "B"), ("A", "C"), ("D", "A")])

    measured = {m.entity.entity_id: m for m in connectivity(view, policy)}

    assert measured["A"].degree == 3
    assert measured["A"].out_degree == 2
    assert measured["A"].in_degree == 1
    assert measured["A"].distinct_neighbours == 3


def test_rank_is_within_the_case_and_dense(policy):
    view = graph([("A", "B"), ("A", "C"), ("A", "D"), ("B", "C")])

    ranked = connectivity(view, policy)

    assert ranked[0].entity.entity_id == "A"
    assert ranked[0].rank == 1
    assert {metric.rank_of for metric in ranked} == {4}
    assert [metric.rank for metric in ranked] == [1, 2, 3, 4]


def test_equal_degrees_rank_in_a_stable_order(policy):
    view = graph([("A", "B"), ("C", "D")])

    first = [m.entity.entity_id for m in connectivity(view, policy)]
    second = [m.entity.entity_id for m in connectivity(view, policy)]

    assert first == second == ["A", "B", "C", "D"]


def test_connectivity_records_the_relationships_behind_it(policy):
    view = graph([("A", "B"), ("A", "C")])

    measured = next(m for m in connectivity(view, policy) if m.entity.entity_id == "A")

    assert measured.supporting_relationship_ids == ("REL-000", "REL-001")
    assert measured.supporting_evidence_ids == ("EV-1",)


def test_entity_types_touched_are_reported(policy):
    view = graph([("P", "D"), ("P", "Q")], types={"D": "Device", "P": "Phone", "Q": "Phone"})

    measured = next(m for m in connectivity(view, policy) if m.entity.entity_id == "P")

    assert measured.entity_types_touched == ("Device", "Phone")


# -- components --------------------------------------------------------------


def test_components_separate_unconnected_groups(policy):
    view = graph([("A", "B"), ("B", "C"), ("X", "Y")])

    groups = components(view, policy)

    assert [group.entity_count for group in groups] == [3, 2]
    assert groups[0].component_id == "CMP-001"
    assert {member.entity_id for member in groups[0].members} == {"A", "B", "C"}


def test_component_identity_is_stable_across_runs(policy):
    view = graph([("A", "B"), ("X", "Y"), ("B", "C")])

    first = [(g.component_id, g.entity_count) for g in components(view, policy)]
    second = [(g.component_id, g.entity_count) for g in components(view, policy)]

    assert first == second


def test_components_report_their_dominant_type(policy):
    view = graph(
        [("P1", "P2"), ("P2", "D1")],
        types={"P1": "Phone", "P2": "Phone", "D1": "Device"},
    )

    group = components(view, policy)[0]

    assert group.dominant_entity_type == "Phone"
    assert group.entity_type_counts == {"Device": 1, "Phone": 2}


# -- bridges -----------------------------------------------------------------


def test_a_bridge_reports_what_it_holds_apart(policy):
    view = graph([("A1", "A2"), ("A2", "A3"), ("BR", "A1"), ("BR", "B1"), ("B1", "B2")])

    found = {metric.entity.entity_id: metric for metric in bridges(view, policy)}

    assert "BR" in found
    assert found["BR"].groups_separated == 2
    assert sorted(found["BR"].group_sizes, reverse=True) == [3, 2]
    assert found["BR"].separated_side_size == 2


def test_a_bridge_between_larger_groups_outranks_one_holding_a_leaf(policy):
    view = graph(
        [("A1", "A2"), ("A2", "A3"), ("BR", "A1"), ("BR", "B1"), ("B1", "B2"), ("A3", "LEAF")]
    )

    ranked = [metric.entity.entity_id for metric in bridges(view, policy)]

    assert ranked.index("BR") < ranked.index("A3")


def test_a_hub_is_a_bridge_and_says_so_plainly(policy):
    """Many people reaching each other only through one number is a fact, not a verdict."""
    view = graph([("H", "C1"), ("H", "C2"), ("H", "C3")])

    found = next(metric for metric in bridges(view, policy) if metric.entity.entity_id == "H")

    assert found.groups_separated == 3
    assert found.separated_side_size == 1


def test_a_single_zero_second_call_is_flagged_as_weak(policy):
    """Zero seconds is a measurement, and a connection resting on it is thin."""
    view = graph(
        [("A", "B"), ("B", "C"), ("C", "STRAY", {"duration": 0})],
    )

    found = next(metric for metric in bridges(view, policy) if metric.entity.entity_id == "C")

    assert found.rests_on_weak_relationship is True


def test_a_substantial_call_is_not_weak(policy):
    view = graph([("A", "B"), ("B", "C"), ("C", "D", {"duration": 400})])

    found = next(metric for metric in bridges(view, policy) if metric.entity.entity_id == "C")

    assert found.rests_on_weak_relationship is False


def test_a_relationship_with_no_duration_is_not_treated_as_brief(policy):
    """Absence of a measurement is not evidence of a short contact."""
    view = graph([("A", "B"), ("B", "C"), ("C", "D", {"kind": "USES"})])

    found = next(metric for metric in bridges(view, policy) if metric.entity.entity_id == "C")

    assert found.rests_on_weak_relationship is False


# -- temporal ----------------------------------------------------------------


def test_undated_relationships_are_not_events(policy):
    """An undated edge must not cluster with every other one at ingestion time."""
    view = graph([("A", "B", {"kind": "USES"}), ("C", "D", {"kind": "USES"})])

    assert temporal_windows(view, policy) == []


def test_events_are_bucketed_into_policy_windows(policy):
    edges = [
        ("A", "B", {"event_at": "2026-03-01T09:05:00+00:00"}),
        ("A", "C", {"event_at": "2026-03-01T09:40:00+00:00"}),
        ("A", "D", {"event_at": "2026-03-01T14:00:00+00:00"}),
    ]

    windows = temporal_windows(graph(edges), policy)

    assert [window.event_count for window in windows] == [2, 1]


def test_a_burst_is_reported_against_the_ordinary_rate(policy):
    edges = [("A", f"N{i}", {"event_at": f"2026-03-0{i + 1}T09:00:00+00:00"}) for i in range(5)]
    edges += [
        ("A", f"B{i}", {"event_at": f"2026-03-09T14:{i * 5:02d}:00+00:00"}) for i in range(8)
    ]

    concentrated = concentrated_windows(graph(edges), policy)

    assert len(concentrated) == 1
    assert concentrated[0].event_count == 8
    assert concentrated[0].concentration_ratio >= policy.temporal.concentration_multiple
    assert concentrated[0].supporting_relationship_ids


def test_a_single_busy_window_is_not_a_concentration(policy):
    """With nothing to compare against, activity is not concentrated."""
    edges = [("A", f"N{i}", {"event_at": f"2026-03-01T09:{i:02d}:00+00:00"}) for i in range(6)]

    assert concentrated_windows(graph(edges), policy) == []


def test_temporal_analysis_is_repeatable(policy):
    edges = [("A", f"N{i}", {"event_at": f"2026-03-01T09:{i:02d}:00+00:00"}) for i in range(4)]
    view = graph(edges)

    assert temporal_windows(view, policy) == temporal_windows(view, policy)


# -- policy ------------------------------------------------------------------


def test_policy_is_data_and_carries_a_version(policy):
    assert policy.analytics_version
    assert policy.limits.max_path_length >= 1
    assert policy.temporal.window_seconds > 0
    assert policy.connectivity.weights


def test_confidence_bands_come_from_policy(policy):
    assert policy.band_for(0.95).band == "HIGH"
    assert policy.band_for(0.0).band == "LOW"
    assert policy.band_for(0.95).minimum_score > policy.band_for(0.0).minimum_score


def test_an_invalid_policy_is_rejected():
    with pytest.raises(AnalyticsPolicyError):
        AnalyticsPolicy.from_dict({"limits": {}})
    with pytest.raises(AnalyticsPolicyError):
        AnalyticsPolicy.from_dict({"analytics_version": "v", "limits": {}})


def test_an_unbounded_path_limit_is_rejected():
    document = {
        "analytics_version": "broken",
        "limits": {
            "max_relationships": 10,
            "max_path_length": 0,
            "max_signals_per_type": 5,
            "max_component_members": 5,
        },
        "connectivity": {},
        "bridge": {},
        "components": {},
        "temporal": {},
        "confidence_bands": [{"band": "LOW", "minimum_score": 0.0}],
    }

    with pytest.raises(AnalyticsPolicyError):
        AnalyticsPolicy.from_dict(document)


# -- vocabulary --------------------------------------------------------------


def test_no_signal_vocabulary_describes_conduct():
    """Analytics reports structure. It never characterises a person."""
    forbidden = {
        "guilty", "criminal", "suspect", "kingpin", "mastermind", "offender",
        "accused", "gang", "perpetrator", "threat", "risk",
    }
    vocabulary = {value.lower() for value in SignalType.__members__}
    vocabulary |= {value.lower() for value in SignalReason.__members__}

    assert not any(word in term for term in vocabulary for word in forbidden)
