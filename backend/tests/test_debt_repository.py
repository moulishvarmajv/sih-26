"""The debt repository's two disciplines: versioning and scope.

Versioning, because a debt record that is overwritten cannot show what the
investigation looked like last week. Scope, because a record computed over one
reader's authorized evidence must be unreachable from another's — the storage
key is where that property is enforced, not a filter someone can forget.
"""
import pytest

from app.core.debt.models import (
    DEBT_ENGINE_VERSION,
    DebtBand,
    DebtBlocker,
    DebtCategory,
    DebtReason,
    DebtSeverity,
    DebtStatus,
    DebtSubject,
    DebtSubjectType,
    DebtWeighting,
    EvidenceDebtItem,
    EvidenceDebtSnapshot,
    build_breakdown,
)
from app.core.debt.repository import EvidenceDebtRepositoryError
from app.infrastructure.sqlite_debt_repository import SQLiteEvidenceDebtRepository

SCOPE = "AAAA111122223333"
OTHER_SCOPE = "BBBB444455556666"
CASE = "CASE-DEBT"


@pytest.fixture
def repository(tmp_path):
    store = SQLiteEvidenceDebtRepository(tmp_path / "debt.db")
    yield store
    store.close()


def weighting(contribution: float = 0.5, scope: int = 2) -> DebtWeighting:
    return DebtWeighting(
        category_weight=1.0,
        severity_multiplier=1.0,
        scope_factor=0.5,
        criticality_factor=1.0,
        affected_scope=scope,
        weighted_contribution=contribution,
    )


def item(
    debt_id: str = "DEBT-1",
    scope_fingerprint: str = SCOPE,
    category: DebtCategory = DebtCategory.CONFLICTING,
    contribution: float = 0.5,
    fingerprint: str = "fact-a",
    status: DebtStatus = DebtStatus.OPEN,
    created_at: str = "2026-03-01T00:00:00+00:00",
) -> EvidenceDebtItem:
    return EvidenceDebtItem(
        debt_id=debt_id,
        case_id=CASE,
        category=category,
        severity=DebtSeverity.HIGH,
        status=status,
        reason=DebtReason.RESOLUTION_ATTRIBUTE_CONFLICT,
        subject=DebtSubject(DebtSubjectType.RESOLUTION, "ERL-1", ("person:aaaa",)),
        weighting=weighting(contribution),
        explanation={"conflict_rule": "DIFFERENT_ACCOUNT_NUMBER"},
        supporting_evidence_ids=("EV-1", "EV-2"),
        related_resolution_ids=("ER-1-v1",),
        related_finding_ids=(),
        created_at=created_at,
        calculated_at="2026-03-01T00:00:00+00:00",
        policy_version="debt-1.0.0",
        debt_engine_version=DEBT_ENGINE_VERSION,
        actionable=True,
        priority=1,
        blocking_reason=DebtBlocker.AWAITING_HUMAN_REVIEW,
        required_capability="REVIEW_ENTITY_RESOLUTION",
        scope_fingerprint=scope_fingerprint,
        fact_fingerprint=fingerprint,
    )


def snapshot(
    snapshot_id: str = "DSNAP-1",
    scope_fingerprint: str = SCOPE,
    total: float = 1.5,
    debt_ids: tuple[str, ...] = ("DEBT-1",),
    items: tuple[EvidenceDebtItem, ...] = (),
) -> EvidenceDebtSnapshot:
    return EvidenceDebtSnapshot(
        snapshot_id=snapshot_id,
        case_id=CASE,
        calculated_at="2026-03-01T00:00:00+00:00",
        calculated_by="USR-104",
        correlation_id="corr-1",
        total_debt=total,
        normalized_debt=0.05,
        band=DebtBand.LOW,
        item_count=len(debt_ids),
        breakdown=build_breakdown(items),
        top_items=items,
        debt_ids=debt_ids,
        evidence_in_scope=3,
        excluded_evidence_count=1,
        scope_fingerprint=scope_fingerprint,
        policy_version="debt-1.0.0",
        debt_engine_version=DEBT_ENGINE_VERSION,
    )


# -- items -------------------------------------------------------------------


def test_an_item_round_trips_with_everything_that_explains_it(repository):
    stored = repository.save_item(item())
    read = repository.get_item("DEBT-1", SCOPE)

    assert read == stored
    assert read.weighting.weighted_contribution == 0.5
    assert read.explanation == {"conflict_rule": "DIFFERENT_ACCOUNT_NUMBER"}
    assert read.subject.entity_refs == ("person:aaaa",)
    assert read.required_capability == "REVIEW_ENTITY_RESOLUTION"


def test_saving_unchanged_facts_writes_nothing_new(repository):
    first = repository.save_item(item())
    second = repository.save_item(item())

    assert second.version == first.version == 1
    assert len(repository.list_item_history("DEBT-1", SCOPE)) == 1


def test_changed_facts_create_a_version_and_keep_the_old_one(repository):
    repository.save_item(item(contribution=0.5, fingerprint="fact-a"))
    revised = repository.save_item(item(contribution=0.9, fingerprint="fact-b"))

    history = repository.list_item_history("DEBT-1", SCOPE)
    assert revised.version == 2
    assert [entry.version for entry in history] == [1, 2]
    assert history[0].status is DebtStatus.SUPERSEDED
    assert history[0].weighting.weighted_contribution == 0.5
    assert history[1].weighting.weighted_contribution == 0.9


def test_a_new_version_keeps_the_date_the_gap_first_appeared(repository):
    repository.save_item(item(created_at="2026-03-01T00:00:00+00:00", fingerprint="a"))
    revised = repository.save_item(item(created_at="2026-04-01T00:00:00+00:00", fingerprint="b"))

    assert revised.created_at == "2026-03-01T00:00:00+00:00"


def test_a_status_transition_is_recorded_on_the_live_version(repository):
    repository.save_item(item())

    updated = repository.update_item_status(
        "DEBT-1", SCOPE, DebtStatus.ACKNOWLEDGED, "2026-03-02T00:00:00+00:00", "USR-104", "seen"
    )

    assert updated.status is DebtStatus.ACKNOWLEDGED
    assert updated.status_changed_by == "USR-104"
    assert updated.status_reason == "seen"
    assert repository.get_item("DEBT-1", SCOPE).status is DebtStatus.ACKNOWLEDGED


def test_resolving_an_item_does_not_delete_it(repository):
    repository.save_item(item())
    repository.update_item_status(
        "DEBT-1", SCOPE, DebtStatus.RESOLVED, "2026-03-03T00:00:00+00:00", "USR-104"
    )

    assert repository.get_item("DEBT-1", SCOPE).status is DebtStatus.RESOLVED
    assert len(repository.list_item_history("DEBT-1", SCOPE)) == 1


def test_a_transition_on_an_unknown_item_is_an_error(repository):
    with pytest.raises(EvidenceDebtRepositoryError):
        repository.update_item_status(
            "DEBT-ABSENT", SCOPE, DebtStatus.RESOLVED, "2026-03-03T00:00:00+00:00", "USR-104"
        )


def test_listing_returns_the_live_version_only(repository):
    repository.save_item(item(contribution=0.5, fingerprint="a"))
    repository.save_item(item(contribution=0.9, fingerprint="b"))

    listed = repository.list_items(CASE)

    assert len(listed) == 1
    assert listed[0].version == 2


def test_listing_orders_by_contribution(repository):
    repository.save_item(item("DEBT-A", contribution=0.2, fingerprint="a"))
    repository.save_item(item("DEBT-B", contribution=0.9, fingerprint="b"))

    assert [entry.debt_id for entry in repository.list_items(CASE)] == ["DEBT-B", "DEBT-A"]


def test_listing_filters_by_category_and_status(repository):
    repository.save_item(item("DEBT-A", category=DebtCategory.CONFLICTING, fingerprint="a"))
    repository.save_item(item("DEBT-B", category=DebtCategory.STALE, fingerprint="b"))
    repository.update_item_status(
        "DEBT-B", SCOPE, DebtStatus.RESOLVED, "2026-03-03T00:00:00+00:00", "USR-104"
    )

    assert [entry.debt_id for entry in repository.list_items(CASE, [DebtCategory.STALE])] == [
        "DEBT-B"
    ]
    assert [
        entry.debt_id for entry in repository.list_items(CASE, statuses=[DebtStatus.OPEN])
    ] == ["DEBT-A"]


# -- scope -------------------------------------------------------------------


def test_the_same_gap_in_two_scopes_is_two_records(repository):
    repository.save_item(item(scope_fingerprint=SCOPE, contribution=0.5, fingerprint="a"))
    repository.save_item(item(scope_fingerprint=OTHER_SCOPE, contribution=0.9, fingerprint="b"))

    assert repository.get_item("DEBT-1", SCOPE).weighting.weighted_contribution == 0.5
    assert repository.get_item("DEBT-1", OTHER_SCOPE).weighting.weighted_contribution == 0.9


def test_a_scope_cannot_read_another_scopes_record(repository):
    repository.save_item(item(scope_fingerprint=OTHER_SCOPE))

    assert repository.get_item("DEBT-1", SCOPE) is None
    assert repository.list_items(CASE, scope_fingerprint=SCOPE) == []


def test_a_transition_in_one_scope_leaves_the_other_alone(repository):
    repository.save_item(item(scope_fingerprint=SCOPE, fingerprint="a"))
    repository.save_item(item(scope_fingerprint=OTHER_SCOPE, fingerprint="a"))

    repository.update_item_status(
        "DEBT-1", SCOPE, DebtStatus.RESOLVED, "2026-03-03T00:00:00+00:00", "USR-104"
    )

    assert repository.get_item("DEBT-1", OTHER_SCOPE).status is DebtStatus.OPEN


# -- snapshots ---------------------------------------------------------------


def test_a_snapshot_round_trips_with_its_breakdown_and_top_items(repository):
    stored = repository.save_snapshot(snapshot(items=(item(),)))
    read = repository.get_snapshot("DSNAP-1")

    assert read.total_debt == stored.total_debt
    assert read.band is DebtBand.LOW
    assert read.persisted is True
    assert len(read.breakdown) == len(DebtCategory)
    assert read.top_items[0].debt_id == "DEBT-1"
    assert read.top_items[0].explanation == {"conflict_rule": "DIFFERENT_ACCOUNT_NUMBER"}


def test_snapshots_accumulate_rather_than_replace(repository):
    repository.save_snapshot(snapshot("DSNAP-1", total=1.0))
    repository.save_snapshot(snapshot("DSNAP-2", total=2.0))

    history = repository.list_snapshots(CASE, SCOPE)

    assert [entry.snapshot_id for entry in history] == ["DSNAP-1", "DSNAP-2"]
    assert repository.latest_snapshot(CASE, SCOPE).snapshot_id == "DSNAP-2"


def test_a_snapshot_id_cannot_be_reused(repository):
    repository.save_snapshot(snapshot("DSNAP-1"))

    with pytest.raises(EvidenceDebtRepositoryError, match="already exists"):
        repository.save_snapshot(snapshot("DSNAP-1"))


def test_the_latest_snapshot_is_scoped(repository):
    repository.save_snapshot(snapshot("DSNAP-1", scope_fingerprint=SCOPE, total=1.0))
    repository.save_snapshot(snapshot("DSNAP-2", scope_fingerprint=OTHER_SCOPE, total=9.0))

    assert repository.latest_snapshot(CASE, SCOPE).total_debt == 1.0
    assert repository.latest_snapshot(CASE, OTHER_SCOPE).total_debt == 9.0


def test_an_unknown_scope_has_no_snapshot(repository):
    repository.save_snapshot(snapshot(scope_fingerprint=OTHER_SCOPE))

    assert repository.latest_snapshot(CASE, SCOPE) is None


def test_snapshots_are_scoped_to_their_case(repository):
    repository.save_snapshot(snapshot("DSNAP-1"))

    assert repository.list_snapshots("CASE-OTHER") == []
