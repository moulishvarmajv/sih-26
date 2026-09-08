"""Credential verification, session lifecycle and login audit events."""
from datetime import timedelta

import pytest

from app.core.audit.event_store import FlightRecorderEvent
from app.core.domain.identity import Clearance
from app.infrastructure.clock import parse_iso, utc_now_iso
from app.security.authentication import (
    AuthenticationError,
    AuthenticationService,
    SessionExpired,
    SessionInvalid,
)
from app.security.identity.local_provider import LocalIdentityProvider
from app.security.identity.models import AccountStatus, AuthenticationOutcome, Credentials
from app.security.identity.passwords import ScryptPasswordHasher
from app.security.identity.seed import INVESTIGATOR
from app.security.identity.user_store import SQLiteUserStore
from app.security.session.store import SQLiteSessionStore, hash_token

PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def hasher():
    # Low cost keeps the suite fast; production parameters live in the class defaults.
    return ScryptPasswordHasher(n=2**8, r=8, p=1)


@pytest.fixture
def user_store(tmp_path, hasher):
    store = SQLiteUserStore(tmp_path / "identity.db")
    store.upsert_role(INVESTIGATOR)
    store.create_account(
        user_id="USR-001",
        username="dev.investigator",
        password_hash=hasher.hash(PASSWORD),
        display_name="Dev Investigator",
        clearance=Clearance(level_code="L2", granted_by="DEV", granted_at=utc_now_iso()),
        role_ids=(INVESTIGATOR.id,),
    )
    store.create_account(
        user_id="USR-003",
        username="dev.disabled",
        password_hash=hasher.hash(PASSWORD),
        display_name="Dev Disabled",
        status=AccountStatus.DISABLED,
        clearance=Clearance(level_code="L1", granted_by="DEV", granted_at=utc_now_iso()),
        role_ids=(INVESTIGATOR.id,),
    )
    yield store
    store.close()


@pytest.fixture
def session_store(tmp_path):
    store = SQLiteSessionStore(tmp_path / "identity.db")
    yield store
    store.close()


@pytest.fixture
def provider(user_store, hasher):
    return LocalIdentityProvider(user_store, hasher)


@pytest.fixture
def auth(provider, session_store, event_store, policy):
    return AuthenticationService(
        identity_provider=provider,
        session_store=session_store,
        event_store=event_store,
        clearance_policy=policy.clearance,
        session_ttl_minutes=60,
    )


def test_password_hashes_are_salted_and_verifiable(hasher):
    first, second = hasher.hash(PASSWORD), hasher.hash(PASSWORD)

    assert first != second  # per-hash salt
    assert PASSWORD not in first
    assert hasher.verify(PASSWORD, first)
    assert not hasher.verify("wrong", first)


def test_valid_credentials_authenticate(provider):
    result = provider.authenticate(Credentials("dev.investigator", PASSWORD))

    assert result.outcome is AuthenticationOutcome.SUCCESS
    assert result.user.id == "USR-001"
    assert result.user.clearance.level_code == "L2"


def test_invalid_password_fails(provider):
    result = provider.authenticate(Credentials("dev.investigator", "wrong"))

    assert result.outcome is AuthenticationOutcome.INVALID_CREDENTIALS
    assert result.user is None


def test_unknown_user_fails_indistinguishably(provider):
    result = provider.authenticate(Credentials("nobody", PASSWORD))

    assert result.outcome is AuthenticationOutcome.INVALID_CREDENTIALS
    assert result.user is None


def test_disabled_account_is_rejected(provider):
    result = provider.authenticate(Credentials("dev.disabled", PASSWORD))

    assert result.outcome is AuthenticationOutcome.ACCOUNT_DISABLED
    assert result.user is None


def test_authenticated_user_carries_no_password_material(provider):
    user = provider.authenticate(Credentials("dev.investigator", PASSWORD)).user

    assert not hasattr(user, "password_hash")
    assert PASSWORD not in repr(user)


def test_login_creates_a_session_with_an_unstored_token(auth, session_store):
    result = auth.login(Credentials("dev.investigator", PASSWORD))

    assert result.token
    assert result.session.user_id == "USR-001"
    assert session_store.get_by_token(result.token).session_id == result.session.session_id

    stored = session_store._connection.execute("SELECT token_hash FROM sessions").fetchone()
    assert stored["token_hash"] == hash_token(result.token)
    assert stored["token_hash"] != result.token


def test_login_emits_login_and_clearance_verified(auth, event_store):
    result = auth.login(Credentials("dev.investigator", PASSWORD))

    login_events = event_store.list_by_type(FlightRecorderEvent.LOGIN)
    clearance_events = event_store.list_by_type(FlightRecorderEvent.CLEARANCE_VERIFIED)

    assert [event.actor_id for event in login_events] == ["USR-001"]
    assert login_events[0].payload["session_id"] == result.session.session_id
    assert len(clearance_events) == 1
    assert clearance_events[0].payload["clearance_level"] == "L2"
    assert result.clearance_verified


def test_login_audit_payload_contains_no_credentials(auth, event_store):
    auth.login(Credentials("dev.investigator", PASSWORD))

    payload = dict(event_store.list_by_type(FlightRecorderEvent.LOGIN)[0].payload)

    assert PASSWORD not in str(payload)
    assert not {"password", "password_hash", "token", "secret"} & set(payload)


def test_failed_login_raises_and_is_audited(auth, event_store):
    with pytest.raises(AuthenticationError):
        auth.login(Credentials("dev.investigator", "wrong"))

    failures = event_store.list_by_type(FlightRecorderEvent.LOGIN_FAILED)
    assert len(failures) == 1
    assert failures[0].payload["outcome"] == "INVALID_CREDENTIALS"
    assert event_store.list_by_type(FlightRecorderEvent.LOGIN) == []


def test_stale_clearance_still_logs_in_but_is_not_verified(
    auth, user_store, event_store, hasher
):
    user_store.create_account(
        user_id="USR-009",
        username="dev.stale",
        password_hash=hasher.hash(PASSWORD),
        display_name="Dev Stale",
        clearance=Clearance(
            level_code="L2",
            granted_by="DEV",
            granted_at="2020-01-01T00:00:00+00:00",
            expires_at="2020-06-01T00:00:00+00:00",
        ),
        role_ids=(INVESTIGATOR.id,),
    )

    result = auth.login(Credentials("dev.stale", PASSWORD))

    assert result.session.user_id == "USR-009"
    assert not result.clearance_verified
    assert event_store.list_by_type(FlightRecorderEvent.CLEARANCE_VERIFIED) == []


def test_resolve_session_returns_the_active_session(auth):
    result = auth.login(Credentials("dev.investigator", PASSWORD))

    assert auth.resolve_session(result.token).session_id == result.session.session_id


def test_unknown_token_is_invalid(auth):
    with pytest.raises(SessionInvalid):
        auth.resolve_session("not-a-real-token")


def test_expired_session_is_rejected_and_marked(provider, session_store, event_store, policy):
    expired_clock = AuthenticationService(
        identity_provider=provider,
        session_store=session_store,
        event_store=event_store,
        clearance_policy=policy.clearance,
        session_ttl_minutes=-1,  # issues an already-expired session
    )
    result = expired_clock.login(Credentials("dev.investigator", PASSWORD))

    with pytest.raises(SessionExpired):
        expired_clock.resolve_session(result.token)

    assert session_store.get_by_token(result.token).status.value == "EXPIRED"


def test_session_expiry_follows_the_configured_ttl(auth):
    result = auth.login(Credentials("dev.investigator", PASSWORD))

    lifetime = parse_iso(result.session.expires_at) - parse_iso(result.session.created_at)
    assert lifetime == timedelta(minutes=60)
