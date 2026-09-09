"""Cross-cutting security regression audit.

The per-domain suites check that *their* routes are protected. These check the
property that has to hold across the whole surface, and they enumerate the
routes from the running application rather than from a list someone maintains
by hand — so a route added later is covered the moment it exists, including one
whose author forgot the session dependency.

Nothing here introduces an authorization concept. It pins down behaviour that
Phases 2-6 already implement:

- identity comes only from the bearer token
- a case-scoped route needs an active agency context
- a case belongs to an agency, and a reader outside it is refused
- unknown and unauthorized resources are indistinguishable
- an error body carries a code, never the data it refused
"""
import pytest

from app.core.domain.case import Case
from app.infrastructure.sources.synthetic_cdr import SyntheticCDRSource
from app.infrastructure.sources.synthetic_subscriber import SyntheticSubscriberRegisterSource
from app.main import app
from tests.api_harness import PASSWORD, build_api_harness

CASE = Case(
    id="CASE-001", agency_id="POLICE", title="Police case", status="OPEN", security_level="L1"
)

#: Reachable without a session, by design.
PUBLIC_PATHS = {"/health", "/ready", "/auth/login", "/docs", "/redoc", "/openapi.json"}

#: Minimal valid bodies, so a route rejects the *caller* rather than the payload.
BODIES = {"/context/switch": {"agency_id": "POLICE"}}

#: Values that exist in the synthetic evidence. None may appear in an error.
RESTRICTED_VALUES = (
    "919876543210",
    "356938035643809",
    "404450123456789",
    "Ananya Sharma",
    "NID-SYNTH-12A",
    "SUB-SYNTH-0001",
)


@pytest.fixture
def wired(tmp_path, event_store, grants, policy):
    """A harness of this test's own.

    Deliberately function-scoped, including for the parametrised sweeps below.
    Sharing one harness across a module runs about ten seconds faster and was
    tried: it produced cumulative interference between cases, because the
    sweeps and the state-changing tests contend over one global
    `dependency_overrides`. Isolation is the property this suite exists to
    protect, so it is not traded for the ten seconds.
    """
    harness = build_api_harness(tmp_path, event_store, grants, policy)
    harness.cases.create(CASE)
    harness.evidence_service.ingest_from_source(CASE, SyntheticCDRSource())
    harness.evidence_service.ingest_from_source(CASE, SyntheticSubscriberRegisterSource())
    grants.grant_case("USR-001", "POLICE", CASE.id, need_to_know=True)
    yield harness
    harness.close()


def protected_routes() -> list[tuple[str, str]]:
    """Every documented route that is not deliberately public."""
    routes = []
    for path, methods in app.openapi()["paths"].items():
        if path in PUBLIC_PATHS:
            continue
        for method in methods:
            routes.append((method.upper(), path))
    return sorted(routes)


#: The evidence routes are scoped by a `case_id` *query* parameter rather than
#: by the path, unlike every other case-scoped route. Without it FastAPI answers
#: 422 before authorization is ever consulted, so these sweeps must supply it.
QUERY_SCOPED_PREFIX = "/evidence/"


def concrete(path: str) -> str:
    url = (
        path.replace("{case_id}", CASE.id)
        .replace("{evidence_id}", "EV-000000000000")
        .replace("{resolution_id}", "ER-000000000000-v1")
    )
    return f"{url}?case_id={CASE.id}" if path.startswith(QUERY_SCOPED_PREFIX) else url


def case_scoped_routes() -> list[tuple[str, str]]:
    """Routes that operate on a case, and therefore need an agency context.

    `/me` and `/context/switch` are session-scoped: requiring a context to
    select one would be circular.
    """
    return [
        (method, path)
        for method, path in protected_routes()
        if "{case_id}" in path or path.startswith(QUERY_SCOPED_PREFIX)
    ]


def request(client, method: str, path: str, headers: dict[str, str] | None = None):
    return client.request(
        method, concrete(path), headers=headers or {}, json=BODIES.get(path)
    )


# -- authentication ----------------------------------------------------------


def test_the_route_table_is_not_empty():
    """Guards the sweeps below: an empty list would make them vacuously pass."""
    assert len(protected_routes()) >= 12
    assert len(case_scoped_routes()) >= 10


@pytest.mark.parametrize("method,path", protected_routes())
def test_every_protected_route_refuses_an_anonymous_caller(wired, method, path):
    response = request(wired.client, method, path)

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "SESSION_INVALID"}


@pytest.mark.parametrize("method,path", protected_routes())
def test_every_protected_route_refuses_a_forged_token(wired, method, path):
    """A token the session store never issued is not a session."""
    response = request(
        wired.client, method, path, {"Authorization": "Bearer not-a-real-token"}
    )

    assert response.status_code == 401


@pytest.mark.parametrize("method,path", case_scoped_routes())
def test_every_case_scoped_route_requires_an_active_agency_context(wired, method, path):
    """Authenticating is not enough: an agency context is a separate step."""
    headers = wired.login()

    response = request(wired.client, method, path, headers)

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "NO_ACTIVE_CONTEXT"}


def test_identity_is_never_taken_from_the_request(wired):
    """A client-supplied user id must not influence who the caller is."""
    headers = wired.authenticate()
    headers["X-User-Id"] = "USR-999"

    body = wired.client.get("/me", headers={**headers}).json()

    assert body["user_id"] == "USR-001"


# -- agency and case scope ---------------------------------------------------


def test_a_reader_in_another_agency_cannot_read_the_case(wired):
    """dev.analyst holds FINANCIAL_CRIME; CASE-001 belongs to POLICE."""
    wired.grants.grant_case("USR-002", "FINANCIAL_CRIME", CASE.id, need_to_know=True)
    headers = wired.authenticate("dev.analyst", agency_id="FINANCIAL_CRIME")

    response = wired.client.get(f"/cases/{CASE.id}/evidence", headers=headers)

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "CASE_ACCESS_DENIED"}


def test_a_context_for_an_unheld_agency_is_refused(wired):
    """USR-002 has no POLICE grant, so it never gets a POLICE context at all."""
    headers = wired.login("dev.analyst")

    response = wired.client.post(
        "/context/switch", json={"agency_id": "POLICE"}, headers=headers
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "AGENCY_ACCESS_DENIED"}


def test_an_unknown_agency_does_not_disclose_the_agency_catalogue(wired):
    headers = wired.login()

    response = wired.client.post(
        "/context/switch", json={"agency_id": "NO-SUCH-AGENCY"}, headers=headers
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "AGENCY_ACCESS_DENIED"}


def test_revoking_a_case_grant_applies_to_the_next_request(wired):
    """Grants are read live, so access is not frozen at login."""
    headers = wired.authenticate()
    assert wired.client.get(f"/cases/{CASE.id}/evidence", headers=headers).status_code == 200

    wired.grants.revoke_case("USR-001", "POLICE", CASE.id)

    assert wired.client.get(f"/cases/{CASE.id}/evidence", headers=headers).status_code == 403


# -- non-disclosure ----------------------------------------------------------


@pytest.mark.parametrize("method,path", protected_routes())
def test_no_error_body_carries_evidence_content(wired, method, path):
    """Denials must not leak the values they refused."""
    headers = wired.authenticate("dev.analyst", agency_id="FINANCIAL_CRIME")

    body = request(wired.client, method, path, headers).text

    for value in RESTRICTED_VALUES:
        assert value not in body


def test_an_unknown_case_answers_like_a_denied_one(wired):
    headers = wired.authenticate()

    unknown = wired.client.get("/cases/CASE-NOPE/evidence", headers=headers)
    denied = wired.client.get(f"/cases/{CASE.id}/evidence", headers=headers)

    assert denied.status_code == 200  # the reader does hold this one
    assert unknown.status_code == 403
    assert unknown.json()["detail"] == {"error": "CASE_ACCESS_DENIED"}


def test_login_does_not_distinguish_its_failure_modes(wired):
    """Unknown user, wrong password and disabled account answer identically."""
    responses = [
        wired.client.post(
            "/auth/login", json={"username": "no.such.user", "password": PASSWORD}
        ),
        wired.client.post(
            "/auth/login", json={"username": "dev.investigator", "password": "wrong"}
        ),
        wired.client.post(
            "/auth/login", json={"username": "dev.disabled", "password": PASSWORD}
        ),
    ]

    assert {response.status_code for response in responses} == {401}
    assert {response.text for response in responses} == {
        '{"detail":{"error":"AUTHENTICATION_FAILED"}}'
    }


# -- privacy -----------------------------------------------------------------


def test_a_partial_reader_receives_no_raw_identifier_anywhere(wired):
    """One sweep across evidence, graph and resolution for an L2 reader."""
    headers = wired.authenticate()
    wired.client.post(f"/cases/{CASE.id}/entity-resolution/run", headers=headers)
    evidence_id = wired.client.get(f"/cases/{CASE.id}/evidence", headers=headers).json()[
        "evidence"
    ][0]["evidence_id"]

    bodies = [
        wired.client.get(
            f"/evidence/{evidence_id}?case_id={CASE.id}", headers=headers
        ).text,
        wired.client.get(f"/cases/{CASE.id}/graph", headers=headers).text,
        wired.client.get(f"/cases/{CASE.id}/entity-resolution", headers=headers).text,
    ]

    for body in bodies:
        assert "919876543210" not in body
        assert "356938035643809" not in body


def test_masking_is_applied_by_the_server_not_requested_of_the_client(wired):
    """The response carries masked values, not raw ones plus an instruction."""
    headers = wired.authenticate()
    evidence_id = wired.client.get(f"/cases/{CASE.id}/evidence", headers=headers).json()[
        "evidence"
    ][0]["evidence_id"]

    body = wired.client.get(
        f"/evidence/{evidence_id}?case_id={CASE.id}", headers=headers
    ).json()

    assert body["decision"] == "PARTIAL"
    assert body["masked_fields"]
    assert all(
        record["caller"].startswith(("+91-XXXX-", "XX-XXXX-"))
        for record in body["payload"]["records"]
    )
