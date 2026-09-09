"""HTTP behaviour of the authentication boundary.

The app is wired to temporary databases through dependency overrides, so these
exercise the real routes, real session store and real authorization service.
"""
import pytest
from fastapi.testclient import TestClient

from app.api import dependencies as deps
from app.core.audit.event_store import FlightRecorderEvent
from app.main import app
from app.security.authentication import AuthenticationService
from app.security.authorization.policy_engine import ClearanceAuthorizationEngine
from app.security.identity.local_provider import LocalIdentityProvider
from app.security.identity.passwords import ScryptPasswordHasher
from app.security.identity.seed import seed_development_identities
from app.security.identity.user_store import SQLiteUserStore
from app.security.service import SecurityService
from app.security.session.store import SQLiteSessionStore

PASSWORD = "dev-only-password"


@pytest.fixture
def wired(tmp_path, event_store, grants, policy):
    hasher = ScryptPasswordHasher(n=2**8, r=8, p=1)
    user_store = SQLiteUserStore(tmp_path / "identity.db")
    session_store = SQLiteSessionStore(tmp_path / "identity.db")
    seed_development_identities(user_store, hasher, PASSWORD, grants)

    auth = AuthenticationService(
        identity_provider=LocalIdentityProvider(user_store, hasher),
        session_store=session_store,
        event_store=event_store,
        clearance_policy=policy.clearance,
        session_ttl_minutes=60,
    )
    security = SecurityService(
        engine=ClearanceAuthorizationEngine(policy),
        grants=grants,
        event_store=event_store,
        clearance_policy=policy.clearance,
    )

    app.dependency_overrides.update(
        {
            deps.get_authentication_service: lambda: auth,
            deps.get_security_service: lambda: security,
            deps.get_session_store: lambda: session_store,
            deps.get_user_store: lambda: user_store,
            deps.get_grant_repository: lambda: grants,
            deps.get_event_store: lambda: event_store,
            deps.get_security_policy: lambda: policy,
        }
    )
    yield TestClient(app)
    app.dependency_overrides.clear()
    user_store.close()
    session_store.close()


def login(client, username="dev.investigator", password=PASSWORD):
    return client.post("/auth/login", json={"username": username, "password": password})


def token_for(client, username="dev.investigator"):
    return login(client, username).json()["token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_valid_login_returns_a_session(wired):
    response = login(wired)

    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == "USR-001"
    assert body["token"]
    assert body["session"]["expires_at"]
    assert body["clearance"] == {"level": "L2", "verified": True, "expires_at": None}


def test_login_response_never_contains_password_material(wired):
    body = login(wired).json()

    serialised = str(body).lower()
    assert PASSWORD not in serialised
    assert "password_hash" not in serialised
    assert "scrypt" not in serialised


def test_invalid_password_is_rejected(wired):
    response = login(wired, password="wrong")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "AUTHENTICATION_FAILED"}


def test_unknown_user_is_indistinguishable_from_a_wrong_password(wired):
    unknown = login(wired, username="nobody")
    wrong_password = login(wired, password="wrong")

    assert unknown.status_code == wrong_password.status_code == 401
    assert unknown.json() == wrong_password.json()


def test_disabled_account_is_rejected_with_the_same_error(wired):
    response = login(wired, username="dev.disabled")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "AUTHENTICATION_FAILED"}


def test_me_requires_authentication(wired):
    response = wired.get("/me")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "SESSION_INVALID"}


def test_me_rejects_an_invalid_session_token(wired):
    response = wired.get("/me", headers=auth_header("forged-token"))

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "SESSION_INVALID"}


def test_me_returns_safe_authenticated_data(wired):
    response = wired.get("/me", headers=auth_header(token_for(wired)))

    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == "USR-001"
    assert body["username"] == "dev.investigator"
    assert body["display_name"] == "Dev Investigator"
    assert body["roles"] == ["INVESTIGATOR"]
    assert body["clearance"]["level"] == "L2"
    assert body["authorized_agencies"] == [{"agency_id": "POLICE", "name": "Police"}]
    assert body["active_agency_id"] is None
    assert PASSWORD not in str(body)


def test_me_ignores_client_supplied_identity(wired):
    """A client cannot select a user; identity comes only from the bearer token."""
    token = token_for(wired, username="dev.analyst")

    response = wired.get(
        "/me",
        headers={**auth_header(token), "X-User-Id": "USR-001"},
        params={"user_id": "USR-001"},
    )

    assert response.status_code == 200
    assert response.json()["user_id"] == "USR-002"


def test_expired_session_is_rejected(wired, tmp_path, event_store, grants, policy):
    hasher = ScryptPasswordHasher(n=2**8, r=8, p=1)
    user_store = SQLiteUserStore(tmp_path / "expired.db")
    session_store = SQLiteSessionStore(tmp_path / "expired.db")
    seed_development_identities(user_store, hasher, PASSWORD, grants)
    expiring = AuthenticationService(
        identity_provider=LocalIdentityProvider(user_store, hasher),
        session_store=session_store,
        event_store=event_store,
        clearance_policy=policy.clearance,
        session_ttl_minutes=-1,
    )
    app.dependency_overrides[deps.get_authentication_service] = lambda: expiring
    token = token_for(wired)

    response = wired.get("/me", headers=auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "SESSION_EXPIRED"}
    user_store.close()
    session_store.close()


def test_authorized_context_switch_succeeds_and_is_audited(wired, event_store):
    token = token_for(wired)

    response = wired.post(
        "/context/switch", json={"agency_id": "POLICE"}, headers=auth_header(token)
    )

    assert response.status_code == 200
    assert response.json() == {
        "agency_id": "POLICE",
        "agency_name": "Police",
        "role": "INVESTIGATOR",
        "clearance_level": "L2",
        "department": None,
        "unit": None,
    }
    assert len(event_store.list_by_type(FlightRecorderEvent.AGENCY_CONTEXT_SWITCHED)) == 1
    assert wired.get("/me", headers=auth_header(token)).json()["active_agency_id"] == "POLICE"


def test_unauthorized_context_switch_is_denied_and_audited(wired, event_store):
    token = token_for(wired)  # USR-001 is granted POLICE only

    response = wired.post(
        "/context/switch", json={"agency_id": "FINANCIAL_CRIME"}, headers=auth_header(token)
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "AGENCY_ACCESS_DENIED"}
    assert len(event_store.list_by_type(FlightRecorderEvent.AGENCY_CONTEXT_DENIED)) == 1
    assert wired.get("/me", headers=auth_header(token)).json()["active_agency_id"] is None


def test_unknown_agency_is_denied_without_disclosing_the_catalogue(wired, event_store):
    response = wired.post(
        "/context/switch",
        json={"agency_id": "NOT_AN_AGENCY"},
        headers=auth_header(token_for(wired)),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "AGENCY_ACCESS_DENIED"}
    assert len(event_store.list_by_type(FlightRecorderEvent.AGENCY_CONTEXT_DENIED)) == 1


def test_context_switch_requires_authentication(wired):
    response = wired.post("/context/switch", json={"agency_id": "POLICE"})

    assert response.status_code == 401


def test_login_and_context_events_are_attributed_to_the_user(wired, event_store):
    token = token_for(wired)
    wired.post("/context/switch", json={"agency_id": "POLICE"}, headers=auth_header(token))

    events = event_store.list_for_user("USR-001")

    assert [event.event_type for event in events] == [
        FlightRecorderEvent.LOGIN,
        FlightRecorderEvent.CLEARANCE_VERIFIED,
        FlightRecorderEvent.AGENCY_CONTEXT_SWITCHED,
    ]
