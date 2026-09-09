"""Evidence debt over the real pipeline, and the boundary it must not cross.

CASE-004 is put through ingestion, the graph, analysis, entity resolution and
analytics, and the debt engine reads what those subsystems recorded. That is the
point: a fixture that handed the detectors a pre-built view would prove the
arithmetic and nothing about the integration.

The mandatory property is checked from both directions. The cleared reader sees
a conflict that exists only because of a restricted register; the uncleared one
finds no trace of it in the total, the counts, the categories, the ids, the
explanations or the trend. The first half is what makes the absence meaningful.
"""
import pytest

from app.core.audit.event_store import FlightRecorderEvent
from app.core.debt.models import (
    DEBT_ENGINE_VERSION,
    DebtBand,
    DebtCategory,
    DebtReason,
    DebtStatus,
    DebtSubjectType,
)
from app.core.debt.policy import load_debt_policy
from app.core.debt.service import (
    DebtAccessDenied,
    DebtItemNotFound,
    EvidenceDebtService,
)
from app.core.analytics.policy import load_analytics_policy
from app.core.analytics.service import GraphAnalyticsService
from app.core.evidence.service import EvidenceService
from app.core.graph.service import GraphService
from app.core.resolution.models import ReviewAction, ResolutionStatus
from app.core.resolution.policy import load_resolution_policy
from app.core.resolution.service import EntityResolutionService
from app.infrastructure.local_object_store import LocalFileEvidenceObjectStore
from app.infrastructure.sqlite_analytics_repository import SQLiteAnalyticsRepository
from app.infrastructure.sqlite_debt_repository import SQLiteEvidenceDebtRepository
from app.infrastructure.sqlite_evidence_repository import SQLiteEvidenceRepository
from app.infrastructure.sqlite_resolution_repository import SQLiteResolutionRepository
from tests.conftest import ANALYST, make_context, make_user
from tests.debt_case import (
    CASE,
    OTHER_CASE,
    RECON_EXPORT,
    RESTRICTED_VALUES,
    build_debt_case,
)
from tests.graph_fakes import InMemoryGraphRepository

READER = "USR-104"


@pytest.fixture
def wiring(tmp_path, security, grants, policy, event_store):
    evidence_repo = SQLiteEvidenceRepository(tmp_path / "investigation.db")
    resolution_repo = SQLiteResolutionRepository(tmp_path / "investigation.db")
    analytics_repo = SQLiteAnalyticsRepository(tmp_path / "investigation.db")
    debt_repo = SQLiteEvidenceDebtRepository(tmp_path / "investigation.db")
    objects = LocalFileEvidenceObjectStore(tmp_path / "objects")
    graph = InMemoryGraphRepository()

    from app.core.evidence.analysis import CdrSummaryAnalyzer

    evidence = EvidenceService(
        evidence_repo, objects, security, event_store, policy.privacy, (CdrSummaryAnalyzer(),)
    )
    graphs = GraphService(graph, evidence_repo, objects, security, event_store, policy.privacy)
    resolution = EntityResolutionService(
        resolution_repository=resolution_repo,
        evidence_repository=evidence_repo,
        object_store=objects,
        graph_repository=graph,
        security=security,
        event_store=event_store,
        policy=load_resolution_policy(),
        privacy=policy.privacy,
    )
    analytics = GraphAnalyticsService(
        graphs, graph, analytics_repo, event_store, load_analytics_policy()
    )
    debt = EvidenceDebtService(
        debt_repository=debt_repo,
        evidence_repository=evidence_repo,
        resolution_repository=resolution_repo,
        analytics_repository=analytics_repo,
        object_store=objects,
        security=security,
        event_store=event_store,
        policy=load_debt_policy(),
    )

    grants.grant_agency(READER, "POLICE")
    for case in (CASE, OTHER_CASE):
        grants.grant_case(READER, "POLICE", case.id, need_to_know=True)

    cleared = reader("L3")
    fixture = build_debt_case(
        evidence_service=evidence,
        graph_service=graphs,
        resolution_service=resolution,
        analytics_service=analytics,
        evidence_repository=evidence_repo,
        user=cleared[0],
        context=cleared[1],
        tmp_path=tmp_path,
    )

    yield {
        "debt": debt,
        "fixture": fixture,
        "evidence": evidence,
        "resolution": resolution,
        "resolution_repo": resolution_repo,
        "analytics": analytics,
        "debt_repo": debt_repo,
        "evidence_repo": evidence_repo,
        "objects": objects,
        "tmp_path": tmp_path,
    }
    for store in (evidence_repo, resolution_repo, analytics_repo, debt_repo):
        store.close()


@pytest.fixture
def debt(wiring):
    return wiring["debt"]


def reader(level="L2", role=None):
    kwargs = {"role": role} if role is not None else {}
    return make_user(READER, level=level), make_context(READER, level=level, **kwargs)


def snapshot(debt, level="L3", case=CASE):
    return debt.calculate(*reader(level), case)


def items(debt, level="L3", case=CASE, **kwargs):
    return debt.list_items(*reader(level), case, **kwargs)


def of(collection, category):
    return [item for item in collection if item.category is category]


def open_ids(debt, category, level="L3"):
    """Debt ids currently standing. Resolved records stay listed, so filter."""
    return {
        item.debt_id
        for item in items(debt, level, statuses=[DebtStatus.OPEN, DebtStatus.ACKNOWLEDGED])
        if item.category is category
    }


# -- the categories, over real pipeline output -------------------------------


def test_the_case_carries_debt_in_every_category_it_was_built_for(debt):
    present = {
        entry.category for entry in snapshot(debt).breakdown if entry.item_count > 0
    }

    assert present == set(DebtCategory)


def test_an_open_identity_decision_is_reported_as_human_review(debt, wiring):
    open_lineages = {
        decision.lineage_id
        for decision in wiring["resolution_repo"].list_decisions(CASE.id)
        if decision.status is ResolutionStatus.REVIEW_REQUIRED
    }

    reported = {
        item.subject.reference for item in of(items(debt), DebtCategory.HUMAN_REVIEW)
    }

    assert reported and reported <= open_lineages


def test_a_pair_below_the_review_floor_is_reported_as_unresolved(debt, wiring):
    candidates = {
        decision.lineage_id
        for decision in wiring["resolution_repo"].list_decisions(CASE.id)
        if decision.status is ResolutionStatus.CANDIDATE
    }

    reported = {item.subject.reference for item in of(items(debt), DebtCategory.UNRESOLVED)}

    assert reported and reported <= candidates


def test_a_recorded_conflict_becomes_debt_that_names_its_rule(debt):
    conflicts = of(items(debt), DebtCategory.CONFLICTING)

    assert conflicts
    assert all("conflict_rule" in item.explanation for item in conflicts)
    assert {
        item.explanation["conflict_rule"] for item in conflicts
    } >= {"DIFFERENT_NATIONAL_ID_REFERENCE"}


def test_a_handset_seen_under_two_identities_is_reported_from_its_analysis(debt):
    internal = [
        item
        for item in of(items(debt), DebtCategory.CONFLICTING)
        if item.reason is DebtReason.OBSERVATIONS_DISAGREE_WITHIN_EVIDENCE
    ]

    assert len(internal) == 1
    assert internal[0].explanation["conflict_metric"] == "imei_with_multiple_imsi_count"
    assert internal[0].explanation["conflict_count"] >= 1


def test_the_reconstructed_export_is_the_only_weak_evidence(debt, wiring):
    weak = of(items(debt), DebtCategory.WEAK)

    assert [item.subject.reference for item in weak] == [wiring["fixture"].weak_evidence_id]
    assert weak[0].explanation["classification"] == "INFERRED"


def test_the_absent_device_registry_is_reported_and_the_present_register_is_not(debt):
    expectations = {
        item.explanation["expectation_id"]
        for item in of(items(debt), DebtCategory.MISSING)
    }

    assert "EXPECT_DEVICE_REGISTRY" in expectations
    assert "EXPECT_SUBSCRIBER_REGISTER" not in expectations


def test_the_export_nobody_analysed_is_reported_as_missing_analysis(debt, wiring):
    missing = [
        item
        for item in of(items(debt), DebtCategory.MISSING)
        if item.reason is DebtReason.EXPECTED_ANALYSIS_ABSENT
    ]

    assert [item.subject.reference for item in missing] == [
        wiring["fixture"].id_of(RECON_EXPORT)
    ]


def test_the_corrected_export_leaves_its_earlier_result_stale(debt, wiring):
    stale = of(items(debt), DebtCategory.STALE)

    assert [item.subject.reference for item in stale] == [wiring["fixture"].stale_evidence_id]
    assert stale[0].explanation["version_count"] == 2
    assert stale[0].explanation["current_result_id"] is None


def test_findings_resting_on_gaps_inherit_them(debt):
    unsupported = of(items(debt), DebtCategory.UNSUPPORTED_FINDING)

    assert unsupported
    assert all(item.subject.subject_type is DebtSubjectType.SIGNAL for item in unsupported)
    assert all(item.related_finding_ids for item in unsupported)


def test_a_finding_resting_on_clean_evidence_carries_no_debt(debt, wiring):
    clean_id = wiring["fixture"].clean_evidence_id
    tainted = {
        item.subject.reference
        for item in of(items(debt), DebtCategory.UNSUPPORTED_FINDING)
    }

    clean_signals = [
        signal
        for signal in wiring["analytics"].list_signals(*reader("L3"), CASE)
        if set(signal.supporting_evidence_ids) == {clean_id}
    ]
    assert clean_signals, "the fixture must contain a finding resting on clean evidence"
    assert all(signal.signal_id not in tainted for signal in clean_signals)


# -- weighting, normalization and bands --------------------------------------


def test_every_item_exposes_the_factors_behind_its_contribution(debt):
    for item in items(debt):
        weighting = item.weighting
        assert weighting.category_weight > 0
        assert weighting.severity_multiplier > 0
        assert 0 < weighting.scope_factor <= 1
        assert weighting.criticality_factor > 0
        assert weighting.weighted_contribution == pytest.approx(
            weighting.category_weight
            * weighting.severity_multiplier
            * weighting.scope_factor
            * weighting.criticality_factor,
            rel=1e-6,
        )


def test_the_total_is_the_sum_of_the_items(debt):
    current = snapshot(debt)

    assert current.total_debt == pytest.approx(
        sum(entry.weighted_contribution for entry in current.breakdown), rel=1e-6
    )


def test_the_breakdown_reports_every_category_including_the_empty_ones(debt):
    current = snapshot(debt, case=OTHER_CASE)

    assert [entry.category for entry in current.breakdown] == list(DebtCategory)


def test_shares_add_up_where_there_is_debt(debt):
    current = snapshot(debt)

    assert sum(entry.share for entry in current.breakdown) == pytest.approx(1.0, abs=1e-4)


def test_a_higher_severity_weighs_more_within_a_category(debt):
    conflicts = of(items(debt), DebtCategory.CONFLICTING)
    blocking = [item for item in conflicts if item.severity.value == "HIGH"]
    minor = [item for item in conflicts if item.severity.value == "MEDIUM"]

    assert blocking and minor
    assert min(item.contribution for item in blocking) > 0
    assert max(item.weighting.severity_multiplier for item in minor) < max(
        item.weighting.severity_multiplier for item in blocking
    )


def test_the_normalized_score_and_band_agree_with_the_policy(debt):
    current = snapshot(debt)
    configured = load_debt_policy()

    assert current.normalized_debt == configured.normalize(current.total_debt)
    assert current.band is configured.band_for(current.normalized_debt)
    assert current.band in set(DebtBand)


def test_the_raw_total_survives_normalization(debt):
    current = snapshot(debt)

    assert current.normalized_debt <= 1.0
    assert current.total_debt > current.normalized_debt


def test_every_item_and_snapshot_names_both_versions(debt):
    current = snapshot(debt)

    assert current.policy_version == load_debt_policy().policy_version
    assert current.debt_engine_version == DEBT_ENGINE_VERSION
    assert all(item.debt_engine_version == DEBT_ENGINE_VERSION for item in items(debt))


# -- determinism and identity ------------------------------------------------


def test_recalculating_unchanged_state_gives_the_same_answer(debt):
    first = snapshot(debt)
    second = snapshot(debt)

    assert first.total_debt == second.total_debt
    assert first.debt_ids == second.debt_ids
    assert [entry.item_count for entry in first.breakdown] == [
        entry.item_count for entry in second.breakdown
    ]


def test_debt_identities_are_stable_across_calculations(debt):
    first = {item.debt_id: item.fact_fingerprint for item in items(debt)}
    second = {item.debt_id: item.fact_fingerprint for item in items(debt)}

    assert first == second


def test_a_recalculation_over_unchanged_state_manufactures_nothing(debt, wiring):
    user, context = reader("L3")
    debt.recalculate(user, context, CASE)
    before = {
        (item.debt_id, item.version) for item in wiring["debt_repo"].list_items(CASE.id)
    }

    debt.recalculate(user, context, CASE)
    after = {(item.debt_id, item.version) for item in wiring["debt_repo"].list_items(CASE.id)}

    assert before == after


def test_a_read_records_nothing(debt, wiring):
    snapshot(debt)
    debt.list_items(*reader("L3"), CASE)

    assert wiring["debt_repo"].list_items(CASE.id) == []
    assert wiring["debt_repo"].list_snapshots(CASE.id) == []


# -- snapshots, history and trend --------------------------------------------


def test_a_recalculation_records_a_snapshot(debt, wiring):
    report = debt.recalculate(*reader("L3"), CASE)

    stored = wiring["debt_repo"].get_snapshot(report.snapshot.snapshot_id)
    assert stored is not None
    assert stored.persisted is True
    assert stored.total_debt == report.snapshot.total_debt
    assert stored.top_items


def test_the_first_calculation_reports_everything_as_newly_introduced(debt):
    report = debt.recalculate(*reader("L3"), CASE)

    assert report.change.previous_snapshot_id is None
    assert set(report.change.introduced_debt_ids) == set(report.snapshot.debt_ids)
    assert report.change.resolved_debt_ids == ()


def test_snapshots_accumulate_rather_than_overwrite(debt, wiring):
    user, context = reader("L3")
    debt.recalculate(user, context, CASE)
    debt.recalculate(user, context, CASE)

    history = debt.snapshots(user, context, CASE)

    assert len(history) == 2
    assert history[0].snapshot_id != history[1].snapshot_id


def test_closing_a_review_moves_the_debt_and_the_trend_shows_it(debt, wiring):
    user, context = reader("L3")
    before = debt.recalculate(user, context, CASE).snapshot

    open_decision = next(
        decision
        for decision in wiring["resolution_repo"].list_decisions(CASE.id)
        if decision.status is ResolutionStatus.REVIEW_REQUIRED
    )
    wiring["resolution"].review(
        user, context, CASE, open_decision.resolution_id, ReviewAction.REJECT, "not the same"
    )

    after = debt.recalculate(user, context, CASE)

    assert after.snapshot.total_debt < before.total_debt
    assert after.change.previous_snapshot_id == before.snapshot_id
    assert after.change.delta < 0
    assert after.change.resolved_debt_ids


def test_history_keeps_what_an_earlier_calculation_concluded(debt, wiring):
    user, context = reader("L3")
    before = debt.recalculate(user, context, CASE).snapshot

    open_decision = next(
        decision
        for decision in wiring["resolution_repo"].list_decisions(CASE.id)
        if decision.status is ResolutionStatus.REVIEW_REQUIRED
    )
    wiring["resolution"].review(
        user, context, CASE, open_decision.resolution_id, ReviewAction.REJECT
    )
    debt.recalculate(user, context, CASE)

    kept = wiring["debt_repo"].get_snapshot(before.snapshot_id)
    assert kept.total_debt == before.total_debt
    assert kept.item_count == before.item_count


# -- lifecycle ---------------------------------------------------------------


def test_a_gap_that_disappears_is_resolved_and_not_deleted(debt, wiring):
    user, context = reader("L3")
    debt.recalculate(user, context, CASE)
    before = open_ids(debt, DebtCategory.HUMAN_REVIEW)

    open_decision = next(
        decision
        for decision in wiring["resolution_repo"].list_decisions(CASE.id)
        if decision.status is ResolutionStatus.REVIEW_REQUIRED
    )
    wiring["resolution"].review(
        user, context, CASE, open_decision.resolution_id, ReviewAction.APPROVE
    )
    debt.recalculate(user, context, CASE)

    closed = before - open_ids(debt, DebtCategory.HUMAN_REVIEW)
    assert closed
    for debt_id in closed:
        record = next(
            item for item in wiring["debt_repo"].list_items(CASE.id) if item.debt_id == debt_id
        )
        assert record.status is DebtStatus.RESOLVED
        assert record.status_reason == "NO_LONGER_DETECTED"


def test_a_resolved_item_stays_readable(debt, wiring):
    user, context = reader("L3")
    debt.recalculate(user, context, CASE)
    open_decision = next(
        decision
        for decision in wiring["resolution_repo"].list_decisions(CASE.id)
        if decision.status is ResolutionStatus.REVIEW_REQUIRED
    )
    before = open_ids(debt, DebtCategory.HUMAN_REVIEW)
    wiring["resolution"].review(
        user, context, CASE, open_decision.resolution_id, ReviewAction.APPROVE
    )
    debt.recalculate(user, context, CASE)

    closed = (before - open_ids(debt, DebtCategory.HUMAN_REVIEW)).pop()
    listed = debt.list_items(user, context, CASE, statuses=[DebtStatus.RESOLVED])

    assert closed in {item.debt_id for item in listed}
    assert debt.get_item(user, context, CASE, closed).status is DebtStatus.RESOLVED


def test_an_acknowledgement_survives_recalculation(debt):
    user, context = reader("L3")
    target = items(debt)[0].debt_id

    acknowledged = debt.acknowledge_item(user, context, CASE, target, "accepted for now")
    assert acknowledged.status is DebtStatus.ACKNOWLEDGED

    debt.recalculate(user, context, CASE)
    after = debt.get_item(user, context, CASE, target)

    assert after.status is DebtStatus.ACKNOWLEDGED
    assert after.status_changed_by == READER
    assert after.status_reason == "accepted for now"


def test_acknowledging_twice_changes_nothing(debt):
    user, context = reader("L3")
    target = items(debt)[0].debt_id

    first = debt.acknowledge_item(user, context, CASE, target)
    second = debt.acknowledge_item(user, context, CASE, target)

    assert first.version == second.version
    assert second.status is DebtStatus.ACKNOWLEDGED


def test_an_items_history_is_recoverable(debt, wiring):
    user, context = reader("L3")
    debt.recalculate(user, context, CASE)
    target = items(debt)[0].debt_id

    history = debt.item_history(user, context, CASE, target)

    assert history
    assert [entry.version for entry in history] == sorted(entry.version for entry in history)


def test_an_unknown_item_is_not_found(debt):
    with pytest.raises(DebtItemNotFound):
        debt.get_item(*reader("L3"), CASE, "DEBT-DOES-NOT-EXIST")


# -- case isolation and authorization ----------------------------------------


def test_debt_is_scoped_to_its_case(debt, wiring):
    other = snapshot(debt, case=OTHER_CASE)
    ours = snapshot(debt)

    assert other.case_id == OTHER_CASE.id
    assert set(other.debt_ids).isdisjoint(ours.debt_ids)


def test_an_item_cannot_be_read_through_the_wrong_case(debt):
    target = items(debt)[0].debt_id

    with pytest.raises(DebtItemNotFound):
        debt.get_item(*reader("L3"), OTHER_CASE, target)


def test_a_reader_without_the_case_is_denied(debt, grants):
    grants.revoke_case(READER, "POLICE", CASE.id)

    with pytest.raises(DebtAccessDenied):
        snapshot(debt)


def test_a_denial_carries_no_investigation_data(debt, grants):
    grants.revoke_case(READER, "POLICE", CASE.id)

    with pytest.raises(DebtAccessDenied) as denied:
        snapshot(debt)

    assert str(denied.value).isupper()
    for value in RESTRICTED_VALUES:
        assert value not in str(denied.value)


def test_a_role_without_the_recalculate_permission_cannot_record(debt):
    user, context = reader("L2", role=ANALYST)

    with pytest.raises(DebtAccessDenied):
        debt.recalculate(user, context, CASE)


def test_a_role_without_the_recalculate_permission_may_still_read(debt):
    user, context = reader("L2", role=ANALYST)

    assert debt.calculate(user, context, CASE).item_count > 0


def test_a_role_without_the_acknowledge_permission_cannot_sign_off(debt):
    user, context = reader("L2", role=ANALYST)
    target = debt.list_items(user, context, CASE)[0].debt_id

    with pytest.raises(DebtAccessDenied):
        debt.acknowledge_item(user, context, CASE, target)


# -- the mandatory restricted-evidence property ------------------------------


def test_a_cleared_reader_sees_the_conflict_the_restricted_register_creates(debt, wiring):
    restricted_id = wiring["fixture"].restricted_evidence_id

    depending = [
        item
        for item in items(debt, "L3")
        if restricted_id in item.supporting_evidence_ids
    ]

    assert depending, "the restricted register must create debt for a cleared reader"
    assert any(item.category is DebtCategory.CONFLICTING for item in depending)


def test_an_uncleared_reader_finds_no_trace_of_the_restricted_evidence(debt, wiring):
    restricted_id = wiring["fixture"].restricted_evidence_id
    cleared_ids = {item.debt_id for item in items(debt, "L3")}
    narrow = items(debt, "L2")

    assert all(
        restricted_id not in item.supporting_evidence_ids for item in narrow
    )
    assert {item.debt_id for item in narrow} < cleared_ids


def test_the_uncleared_total_omits_the_restricted_debt_rather_than_hiding_it(debt):
    cleared = snapshot(debt, "L3")
    narrow = snapshot(debt, "L2")

    assert narrow.total_debt < cleared.total_debt
    assert narrow.item_count < cleared.item_count
    # No "hidden items" counter anywhere: the omitted debt leaves no residue.
    assert sum(entry.item_count for entry in narrow.breakdown) == narrow.item_count


def test_no_restricted_value_appears_anywhere_in_an_uncleared_answer(debt):
    user, context = reader("L2")
    rendered = str(
        [
            debt.report(user, context, CASE),
            debt.list_items(user, context, CASE),
            debt.breakdown(user, context, CASE),
        ]
    )

    for value in RESTRICTED_VALUES:
        assert value not in rendered


def test_an_uncleared_reader_cannot_read_a_restricted_item_by_its_id(debt, wiring):
    restricted_id = wiring["fixture"].restricted_evidence_id
    hidden = next(
        item
        for item in items(debt, "L3")
        if restricted_id in item.supporting_evidence_ids
    )

    with pytest.raises(DebtItemNotFound):
        debt.get_item(*reader("L2"), CASE, hidden.debt_id)


def test_the_trend_never_compares_across_scopes(debt):
    cleared_user, cleared_context = reader("L3")
    debt.recalculate(cleared_user, cleared_context, CASE)

    narrow = debt.report(*reader("L2"), CASE)

    assert narrow.change.previous_snapshot_id is None
    assert narrow.change.previous_total == 0.0


def test_a_narrow_reader_cannot_close_a_gap_they_cannot_see(debt, wiring):
    cleared_user, cleared_context = reader("L3")
    debt.recalculate(cleared_user, cleared_context, CASE)
    restricted_id = wiring["fixture"].restricted_evidence_id
    hidden = [
        item
        for item in wiring["debt_repo"].list_items(CASE.id)
        if restricted_id in item.supporting_evidence_ids
    ]
    assert hidden

    debt.recalculate(*reader("L2"), CASE)

    still_open = [
        item
        for item in wiring["debt_repo"].list_items(CASE.id)
        if restricted_id in item.supporting_evidence_ids
    ]
    assert {item.debt_id for item in still_open} == {item.debt_id for item in hidden}
    assert all(item.status is DebtStatus.OPEN for item in still_open)


def test_the_reader_is_told_how_much_evidence_is_out_of_scope_not_what_it_says(debt):
    narrow = snapshot(debt, "L2")

    assert narrow.excluded_evidence_count == 1
    assert narrow.evidence_in_scope == 5
    for value in RESTRICTED_VALUES:
        assert value not in str(narrow.breakdown)


def test_identifiers_are_never_carried_in_a_debt_item(debt):
    """Entities travel as the hashed refs resolution and the graph already use."""
    for item in items(debt, "L3"):
        for ref in item.subject.entity_refs:
            assert ":" in ref
            assert not any(character.isdigit() for character in ref.split(":")[0])
        assert "919840" not in str(item.explanation)


# -- audit -------------------------------------------------------------------


def test_a_recalculation_is_audited_end_to_end(debt, event_store):
    debt.recalculate(*reader("L3"), CASE)

    recorded = {event.event_type for event in event_store.list_for_case(CASE.id)}

    assert FlightRecorderEvent.EVIDENCE_DEBT_CALCULATION_STARTED in recorded
    assert FlightRecorderEvent.EVIDENCE_DEBT_CALCULATION_COMPLETED in recorded
    assert FlightRecorderEvent.EVIDENCE_DEBT_CREATED in recorded


def test_a_second_recalculation_records_no_spurious_creations(debt, event_store):
    user, context = reader("L3")
    debt.recalculate(user, context, CASE)
    before = sum(
        1
        for event in event_store.list_for_case(CASE.id)
        if event.event_type is FlightRecorderEvent.EVIDENCE_DEBT_CREATED
    )

    debt.recalculate(user, context, CASE)
    after = sum(
        1
        for event in event_store.list_for_case(CASE.id)
        if event.event_type is FlightRecorderEvent.EVIDENCE_DEBT_CREATED
    )

    assert after == before


def test_closing_a_gap_is_audited(debt, wiring, event_store):
    user, context = reader("L3")
    debt.recalculate(user, context, CASE)
    open_decision = next(
        decision
        for decision in wiring["resolution_repo"].list_decisions(CASE.id)
        if decision.status is ResolutionStatus.REVIEW_REQUIRED
    )
    wiring["resolution"].review(
        user, context, CASE, open_decision.resolution_id, ReviewAction.APPROVE
    )
    debt.recalculate(user, context, CASE)

    resolved = [
        event
        for event in event_store.list_for_case(CASE.id)
        if event.event_type is FlightRecorderEvent.EVIDENCE_DEBT_RESOLVED
    ]

    assert resolved
    assert resolved[0].payload["reason"] == "NO_LONGER_DETECTED"


def test_an_acknowledgement_is_audited_as_a_revision(debt, event_store):
    user, context = reader("L3")
    debt.acknowledge_item(user, context, CASE, items(debt)[0].debt_id)

    revised = [
        event
        for event in event_store.list_for_case(CASE.id)
        if event.event_type is FlightRecorderEvent.EVIDENCE_DEBT_REVISED
    ]

    assert revised
    assert revised[-1].payload["status"] == "ACKNOWLEDGED"


def test_a_denied_debt_read_is_audited(debt, grants, event_store):
    grants.revoke_case(READER, "POLICE", CASE.id)
    with pytest.raises(DebtAccessDenied):
        snapshot(debt)

    denied = [
        event
        for event in event_store.list_for_case(CASE.id)
        if event.event_type is FlightRecorderEvent.EVIDENCE_DEBT_ACCESS_DENIED
    ]

    assert denied
    assert denied[-1].payload["action"] == "VIEW_EVIDENCE_DEBT"


def test_audit_payloads_explain_without_the_data(debt, event_store):
    debt.recalculate(*reader("L3"), CASE)

    for event in event_store.list_for_case(CASE.id):
        if not event.event_type.value.startswith("EVIDENCE_DEBT"):
            continue
        rendered = str(event.payload)
        for value in RESTRICTED_VALUES:
            assert value not in rendered


# -- the vocabulary ----------------------------------------------------------


def test_nothing_in_the_debt_vocabulary_describes_conduct(debt):
    """Debt is an investigation-quality metric. It says nothing about anyone."""
    forbidden = (
        "GUILT",
        "SUSPECT",
        "CRIMINAL",
        "CULPABLE",
        "RISK",
        "THREAT",
        "SCORE_OF_GUILT",
        "CONVICTION",
        "COMPLETION",
    )
    vocabulary = " ".join(
        member.value
        for enum in (DebtCategory, DebtReason, DebtBand, DebtStatus, DebtSubjectType)
        for member in enum
    ).upper()

    for word in forbidden:
        assert word not in vocabulary
