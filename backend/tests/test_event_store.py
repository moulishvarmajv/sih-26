"""SQLite flight recorder: append, retrieval, ordering, and append-only surface."""
import pytest

from app.core.audit.event_store import (
    ActorType,
    EventDraft,
    EventStore,
    EventStoreError,
    FlightRecorderEvent,
)
from app.infrastructure.sqlite_event_store import SQLiteEventStore


@pytest.fixture
def store(tmp_path):
    event_store = SQLiteEventStore(tmp_path / "events.db")
    yield event_store
    event_store.close()


def draft(
    event_type=FlightRecorderEvent.CASE_CREATED,
    case_id="CASE-001",
    actor_id="USR-104",
    payload=None,
):
    return EventDraft(
        event_type=event_type,
        actor_id=actor_id,
        actor_type=ActorType.USER,
        correlation_id="corr-1",
        case_id=case_id,
        payload=payload or {"note": "seeded"},
    )


def test_append_returns_stored_event_and_get_reads_it_back(store):
    stored = store.append(draft(payload={"beta": 2, "alpha": 1}))

    assert stored.sequence == 1
    assert stored.event_id
    assert stored.occurred_at

    fetched = store.get(stored.event_id)
    assert fetched is not None
    assert fetched.event_id == stored.event_id
    assert fetched.event_type is FlightRecorderEvent.CASE_CREATED
    assert fetched.actor_type is ActorType.USER
    assert dict(fetched.payload) == {"alpha": 1, "beta": 2}


def test_get_unknown_event_returns_none(store):
    assert store.get("does-not-exist") is None


def test_events_preserve_append_ordering(store):
    for index in range(5):
        store.append(draft(payload={"index": index}))

    events = store.list_for_case("CASE-001")

    assert [event.sequence for event in events] == [1, 2, 3, 4, 5]
    assert [event.payload["index"] for event in events] == [0, 1, 2, 3, 4]


def test_list_for_case_filters_by_case(store):
    store.append(draft(case_id="CASE-001"))
    store.append(draft(case_id="CASE-002"))
    store.append(draft(case_id="CASE-001"))

    assert [event.case_id for event in store.list_for_case("CASE-001")] == ["CASE-001"] * 2
    assert len(store.list_for_case("CASE-002")) == 1
    assert store.list_for_case("CASE-404") == []


def test_list_for_user_and_by_type_filter_independently(store):
    store.append(draft(actor_id="USR-1", event_type=FlightRecorderEvent.LOGIN))
    store.append(draft(actor_id="USR-2", event_type=FlightRecorderEvent.LOGIN))
    store.append(draft(actor_id="USR-1", event_type=FlightRecorderEvent.GRAPH_UPDATED))

    assert len(store.list_for_user("USR-1")) == 2
    assert len(store.list_by_type(FlightRecorderEvent.LOGIN)) == 2
    assert len(store.list_by_type(FlightRecorderEvent.TASK_FAILED)) == 0


def test_store_exposes_no_update_or_delete_operations():
    for surface in (EventStore, SQLiteEventStore):
        attributes = dir(surface)
        assert not [
            name
            for name in attributes
            if any(verb in name.lower() for verb in ("update", "delete", "remove", "truncate"))
        ]


def test_payload_must_be_json_serialisable(store):
    with pytest.raises(EventStoreError):
        store.append(draft(payload={"bad": object()}))


def test_payload_serialisation_is_deterministic(store):
    first = store.append(draft(payload={"b": 1, "a": 2}))
    second = store.append(draft(payload={"a": 2, "b": 1}))

    row_one = store.get(first.event_id)
    row_two = store.get(second.event_id)
    assert dict(row_one.payload) == dict(row_two.payload)
    assert list(row_one.payload) == list(row_two.payload)
