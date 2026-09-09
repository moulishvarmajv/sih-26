"""Deterministic graph metrics over an authorized case view.

Pure: a function of (graph view, policy). No storage, no clock, no randomness,
no model. The same view and the same policy version always produce the same
metrics in the same order, which is what lets a signal be re-derived and checked
months later.

Determinism is not automatic for graph algorithms — most of them iterate over
sets. Every traversal here starts from a sorted node list and every result is
sorted before it is returned, so nothing depends on hash ordering.

The algorithms are written out rather than pulled from a library. Connected
components is a union-find; bridges are Hopcroft-Tarjan articulation points,
iterative so a deep graph cannot exhaust the stack. Both are short, both are
tested against graphs whose answers are known by hand, and neither needs a
dependency that would otherwise exist only for them.

**Why articulation points and not betweenness centrality.** Betweenness gives a
number; an articulation point gives a statement an investigator can check:
*without this entity, these groups have no connection in the authorized graph*.
This phase requires every signal to be explainable, and a threshold on a
centrality score is not an explanation.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Mapping, Sequence

from app.core.analytics.graph_view import AnalysableGraph, ViewRelationship
from app.core.analytics.models import (
    BridgeMetric,
    ConnectivityMetric,
    GraphComponent,
    TemporalWindow,
)
from app.core.analytics.policy import AnalyticsPolicy
from app.infrastructure.clock import parse_iso

# -- connectivity ------------------------------------------------------------


def connectivity(graph: AnalysableGraph, policy: AnalyticsPolicy) -> list[ConnectivityMetric]:
    """Degree measurements for every entity, ranked within the case.

    Rank is deterministic: ordered by degree descending, then by entity id, so
    two entities with equal degree always rank in the same order rather than in
    whatever order the graph was read.
    """
    incident: dict[str, list[ViewRelationship]] = defaultdict(list)
    in_degree: dict[str, int] = defaultdict(int)
    out_degree: dict[str, int] = defaultdict(int)

    for relationship in graph.relationships:
        for entity_id in {relationship.source_id, relationship.target_id}:
            incident[entity_id].append(relationship)
        out_degree[relationship.source_id] += 1
        in_degree[relationship.target_id] += 1

    measured = []
    for entity_id in sorted(graph.entities):
        relationships = incident.get(entity_id, [])
        neighbours = graph.neighbours(entity_id)
        types = sorted(
            {
                graph.entities[neighbour].entity_type
                for neighbour in neighbours
                if neighbour in graph.entities
            }
        )
        measured.append(
            (
                len(relationships),
                entity_id,
                types,
                relationships,
                len(neighbours),
                in_degree.get(entity_id, 0),
                out_degree.get(entity_id, 0),
            )
        )

    measured.sort(key=lambda item: (-item[0], item[1]))
    total = len(graph.entities)
    return [
        ConnectivityMetric(
            entity=graph.entities[entity_id],
            degree=degree,
            in_degree=incoming,
            out_degree=outgoing,
            distinct_neighbours=neighbour_count,
            entity_types_touched=tuple(types),
            rank=index + 1,
            rank_of=total,
            supporting_relationship_ids=tuple(
                sorted(relationship.relationship_id for relationship in relationships)
            ),
            supporting_evidence_ids=_evidence_of(relationships),
        )
        for index, (
            degree,
            entity_id,
            types,
            relationships,
            neighbour_count,
            incoming,
            outgoing,
        ) in enumerate(measured)
    ]


# -- components --------------------------------------------------------------


def components(graph: AnalysableGraph, policy: AnalyticsPolicy) -> list[GraphComponent]:
    """Connected groups within the authorized graph, largest first.

    Union-find over the undirected adjacency. Ordering is by size descending
    then by smallest member id, so the same graph always yields the same
    component order and therefore the same component identifiers.
    """
    parent = {entity_id: entity_id for entity_id in graph.entities}

    def find(node: str) -> str:
        root = node
        while parent[root] != root:
            root = parent[root]
        while parent[node] != root:  # path compression
            parent[node], node = root, parent[node]
        return root

    for relationship in graph.relationships:
        left, right = relationship.source_id, relationship.target_id
        if left not in parent or right not in parent:
            continue
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            # Union onto the smaller id, so the representative does not depend
            # on the order relationships happened to arrive in.
            low, high = sorted((left_root, right_root))
            parent[high] = low

    grouped: dict[str, list[str]] = defaultdict(list)
    for entity_id in sorted(graph.entities):
        grouped[find(entity_id)].append(entity_id)

    relationships_by_root: dict[str, list[ViewRelationship]] = defaultdict(list)
    for relationship in graph.relationships:
        if relationship.source_id in parent:
            relationships_by_root[find(relationship.source_id)].append(relationship)

    ordered = sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0]))
    result: list[GraphComponent] = []
    for index, (root, members) in enumerate(ordered):
        if len(members) < policy.components.minimum_members:
            continue
        type_counts: dict[str, int] = defaultdict(int)
        for member in members:
            type_counts[graph.entities[member].entity_type] += 1
        dominant = sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
        group_relationships = relationships_by_root.get(root, [])
        capped = members[: policy.limits.max_component_members]
        result.append(
            GraphComponent(
                component_id=f"CMP-{index + 1:03d}",
                members=tuple(graph.entities[member] for member in capped),
                entity_count=len(members),
                relationship_count=len(group_relationships),
                entity_type_counts=dict(sorted(type_counts.items())),
                dominant_entity_type=dominant,
                supporting_evidence_ids=_evidence_of(group_relationships),
            )
        )
    return result


# -- bridges -----------------------------------------------------------------


def articulation_points(adjacency: Mapping[str, frozenset[str]]) -> set[str]:
    """Entities whose removal increases the number of connected groups.

    Hopcroft-Tarjan, written iteratively: recursion reads more simply, but a
    long chain in a case graph would hit Python's recursion limit, and failing
    an analysis because a graph was deep is not an acceptable answer.
    """
    order: dict[str, int] = {}
    low: dict[str, int] = {}
    parent: dict[str, str | None] = {}
    cut: set[str] = set()
    counter = 0

    for root in sorted(adjacency):
        if root in order:
            continue
        parent[root] = None
        root_children = 0
        order[root] = low[root] = counter
        counter += 1
        # Each frame is (node, its sorted neighbours, how many are consumed).
        stack: list[tuple[str, list[str], int]] = [(root, sorted(adjacency[root]), 0)]

        while stack:
            node, neighbours, index = stack[-1]
            if index < len(neighbours):
                stack[-1] = (node, neighbours, index + 1)
                neighbour = neighbours[index]
                if neighbour == parent.get(node) or neighbour not in adjacency:
                    continue
                if neighbour in order:
                    low[node] = min(low[node], order[neighbour])
                    continue
                parent[neighbour] = node
                order[neighbour] = low[neighbour] = counter
                counter += 1
                if node == root:
                    root_children += 1
                stack.append((neighbour, sorted(adjacency[neighbour]), 0))
                continue

            stack.pop()
            if not stack:
                continue
            ancestor = stack[-1][0]
            low[ancestor] = min(low[ancestor], low[node])
            # A non-root separates the graph when a child's subtree cannot reach
            # above it except by passing through it.
            if ancestor != root and low[node] >= order[ancestor]:
                cut.add(ancestor)

        if root_children > 1:
            # The root separates the graph only when it has more than one child
            # in the depth-first tree.
            cut.add(root)
    return cut


def separated_regions(
    adjacency: Mapping[str, frozenset[str]], entity_id: str
) -> list[frozenset[str]]:
    """The parts the graph falls into once this entity is removed.

    Whole regions, not just the entity's immediate neighbours. "Removing this
    phone leaves a group of six and a group of five with no route between them"
    is the finding; "it has two neighbours" is not, and counting neighbours
    would rank a hub with four hangers-on above a phone holding two real groups
    apart.

    Only the regions reachable from this entity's neighbours are returned —
    parts of the graph it was never attached to are unaffected by its removal.
    """
    neighbours = sorted(adjacency.get(entity_id, frozenset()))
    unvisited = set(neighbours)
    regions: list[frozenset[str]] = []

    while unvisited:
        start = min(unvisited)
        seen = {start}
        queue = deque([start])
        while queue:
            node = queue.popleft()
            for candidate in sorted(adjacency.get(node, frozenset())):
                if candidate == entity_id or candidate in seen:
                    continue
                seen.add(candidate)
                queue.append(candidate)
        regions.append(frozenset(seen))
        unvisited -= seen
    return sorted(regions, key=lambda region: (-len(region), sorted(region)[0]))


def bridges(graph: AnalysableGraph, policy: AnalyticsPolicy) -> list[BridgeMetric]:
    """Entities that hold otherwise separate parts of the authorized graph together.

    An entity qualifies when removing it separates the graph *and* it meets the
    policy's minimum for how many groups it joins. Spanning several entity types
    — a phone linking two people, a person linking a phone and a handset — is
    recorded as cross-domain reach, and raises the score without being required
    on its own.
    """
    cut_vertices = articulation_points(graph.adjacency)
    results: list[BridgeMetric] = []

    for entity_id in sorted(cut_vertices):
        entity = graph.entities.get(entity_id)
        if entity is None:
            continue
        regions = separated_regions(graph.adjacency, entity_id)
        if len(regions) < policy.bridge.minimum_groups_connected:
            continue
        incident = graph.incident(entity_id)
        types = sorted(
            {
                graph.entities[neighbour].entity_type
                for neighbour in graph.neighbours(entity_id)
                if neighbour in graph.entities
            }
        )
        # A connection resting on one short relationship is still a connection,
        # but it is a weak one, and the signal says so rather than letting the
        # structure speak for itself.
        weak = _rests_on_weak_relationship(
            incident, regions, graph, policy.bridge.weak_relationship_duration_seconds
        )
        results.append(
            BridgeMetric(
                entity=entity,
                groups_separated=len(regions),
                group_sizes=tuple(len(region) for region in regions),
                # The largest part cut off from the main body: what this entity
                # actually holds apart, rather than how many pieces there are.
                separated_side_size=len(regions[1]) if len(regions) > 1 else 0,
                entity_types_spanned=tuple(types),
                neighbour_count=len(graph.neighbours(entity_id)),
                rests_on_weak_relationship=weak,
                supporting_relationship_ids=tuple(
                    sorted(relationship.relationship_id for relationship in incident)
                ),
                supporting_evidence_ids=_evidence_of(incident),
            )
        )
    results.sort(
        key=lambda metric: (
            -metric.separated_side_size,
            -metric.groups_separated,
            metric.entity.entity_id,
        )
    )
    return results


def _rests_on_weak_relationship(
    incident: Sequence[ViewRelationship],
    regions: Sequence[frozenset[str]],
    graph: AnalysableGraph,
    weak_seconds: int,
) -> bool:
    """True when some group is joined only by short-duration relationships.

    Durations come from the source: a CDR records how long a call lasted, and a
    call of zero seconds is a measurement, not a missing one. A relationship
    that carries no duration at all is left alone — absence of a measurement is
    not evidence of a brief contact.
    """
    if weak_seconds <= 0:
        return False
    for region in regions:
        joining = [
            relationship
            for relationship in incident
            if relationship.source_id in region or relationship.target_id in region
        ]
        measured = [
            relationship for relationship in joining if relationship.duration_measured
        ]
        if len(joining) != 1 or not measured:
            continue
        if all(relationship.duration_seconds <= weak_seconds for relationship in measured):
            return True
    return False


# -- temporal ----------------------------------------------------------------


def temporal_windows(
    graph: AnalysableGraph, policy: AnalyticsPolicy
) -> list[TemporalWindow]:
    """Fixed-width buckets of observed events, and how each compares with the rest.

    Windows are anchored at the earliest event in the authorized graph, so the
    buckets depend on the data rather than on when the analysis happened to run
    — the same evidence analysed tomorrow lands in the same windows.

    The comparison baseline is the mean over *occupied* windows, not over the
    whole span. A case with one busy afternoon inside a quiet year would
    otherwise show every window as a concentration, which says more about the
    span than about the activity.
    """
    dated: list[tuple[float, ViewRelationship]] = []
    for relationship in graph.relationships:
        if relationship.event_at is None:
            continue  # undated: the source never said when this happened
        moment = _epoch(relationship.event_at)
        if moment is not None:
            dated.append((moment, relationship))
    if not dated:
        return []

    dated.sort(key=lambda item: (item[0], item[1].relationship_id))
    origin = dated[0][0]
    width = max(1, policy.temporal.window_seconds)

    buckets: dict[int, list[ViewRelationship]] = defaultdict(list)
    for moment, relationship in dated:
        buckets[int((moment - origin) // width)].append(relationship)

    occupied = [len(items) for items in buckets.values()]
    mean = sum(occupied) / len(occupied)

    windows: list[TemporalWindow] = []
    for index in sorted(buckets):
        items = buckets[index]
        ratio = len(items) / mean if mean > 0 else 0.0
        windows.append(
            TemporalWindow(
                window_start=_iso(origin + index * width),
                window_end=_iso(origin + (index + 1) * width),
                event_count=len(items),
                mean_event_count=round(mean, 4),
                concentration_ratio=round(ratio, 4),
                supporting_relationship_ids=tuple(
                    sorted(relationship.relationship_id for relationship in items)
                ),
                supporting_evidence_ids=_evidence_of(items),
            )
        )
    return windows


def concentrated_windows(
    graph: AnalysableGraph, policy: AnalyticsPolicy
) -> list[TemporalWindow]:
    """The windows that meet the policy's bar for a concentration signal."""
    temporal = policy.temporal
    selected = [
        window
        for window in temporal_windows(graph, policy)
        if window.event_count >= temporal.minimum_events_in_window
        and window.concentration_ratio >= temporal.concentration_multiple
    ]
    selected.sort(key=lambda window: (-window.concentration_ratio, window.window_start))
    return selected


# -- helpers -----------------------------------------------------------------


def _evidence_of(relationships: Sequence[ViewRelationship]) -> tuple[str, ...]:
    return tuple(
        sorted({relationship.evidence_id for relationship in relationships if relationship.evidence_id})
    )


def _epoch(value: str) -> float | None:
    try:
        return parse_iso(value).timestamp()
    except (TypeError, ValueError):
        return None


def _iso(epoch: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
