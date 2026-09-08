# SHADOW-INTEL — Implementation State

_Update as phases land — do not let this drift from reality._

## Completed

### Phase 1 — module boundaries and contracts
- Module structure under `backend/app/`: `core/{domain,evidence,execution,graph,audit,investigation,navigator}`, `security/{identity,roles,clearance,policy,authorization,privacy}`, `plugins/`, `infrastructure/`, `api/`.
- Typed contracts (`typing.Protocol`): `AgencyPlugin`, `EvidenceSource`, `GraphRepository`, `TaskExecutor`, `IdentityProvider`, `AuthorizationEngine`, `EventStore`, `IntegrityProvider`.
- Working `PluginRegistry` (register / get / discover / enable / disable, with validation and duplicate rejection).
- FastAPI entry point with `/health` and `/ready`, structured logging + correlation-ID middleware, `backend/.env.example`, `pytest.ini`, backend `Dockerfile` and root `docker-compose.yml` (backend + local Neo4j community container).

### Phase 2 — security and audit foundation
- **SQLite EventStore** (`app/infrastructure/sqlite_event_store.py`): `append` / `get` / `list_for_case` / `list_for_user` / `list_by_type`, ordered by a store-assigned sequence. Append-only at the application layer (no update/delete on the interface; event id, sequence and timestamp are assigned by the store, not the caller). Deterministic payload serialisation (sorted keys, compact separators), indexes on case/type/actor/time, explicit `EventStoreError`.
- **Policy as data** (`app/security/policy/clearance_policy.json`): synthetic levels L1=INTERNAL, L2=CONFIDENTIAL, L3=RESTRICTED with ranks, a fail-closed `default_required_level`, and a privacy section (`unmask_minimum_level`, `maskable_fields`). Loaded via `load_security_policy()`; no level string comparisons in business logic.
- **AuthorizationEngine** (`app/security/authorization/policy_engine.py`): pure function of (request, facts, policy) producing ALLOW / PARTIAL / DENY with a deterministic `ReasonCode`. Fixed check order: identity → clearance validity → context escalation → agency → case/agency match → case → evidence/case match → need-to-know → role → clearance rank → privacy masking.
- **AgencyContext as a runtime claim** (`core/domain/agency.py`): agency, department, unit, role, clearance, policy profile, user identity. Re-evaluated on every call; a context claiming more clearance than the user holds is denied (`CONTEXT_CLEARANCE_ESCALATION`).
- **AuthorizationDecision** (`core/domain/authorization.py`): effect, reason, user, agency, action, case/evidence ids, user + required clearance, agency/case/need-to-know flags, privacy action, redacted field *names*, timestamp, correlation id, plus an audit-safe `to_audit_payload()`. Carries no resource content.
- **SecurityService** (`app/security/service.py`): `authorize_agency_context`, `authorize_case_access`, `authorize_evidence_access`, `authorize_action`. Resolves facts from `AccessGrantRepository`, delegates the decision to the engine, and records every outcome to the EventStore.
- **Audit events**: `EVIDENCE_ACCESS_ALLOWED` / `EVIDENCE_ACCESS_DENIED` / `EVIDENCE_REDACTED`, `CASE_ACCESS_ALLOWED` / `CASE_ACCESS_DENIED`, `AGENCY_CONTEXT_SWITCHED` / `AGENCY_CONTEXT_DENIED`, `ACTION_ALLOWED` / `ACTION_DENIED`. The last five extend the original architecture list so that *denials* are auditable too.
- **Composition root** (`app/api/dependencies.py`) so future routes inject `SecurityService` and never evaluate policy themselves.
- **51 tests** covering the clearance/privacy policy, the full decision matrix, and event persistence.

## In progress

Nothing. Phase 2 is complete and committed.

## Next — exactly one subsystem

**IdentityProvider + login flow** (`app/security/identity/`): resolve an authenticated `User` (with roles and clearance) from a credential, emit `LOGIN` and `CLEARANCE_VERIFIED` to the flight recorder, and expose the first authenticated route wired through `SecurityService`. This is the only remaining piece that keeps `SecurityService` from being reachable over HTTP.

Do not start Neo4j ingestion, evidence adapters, entity resolution, analytics, the navigator, the frontend, or blockchain work before that.

## Known limitations

- **No real government IdP.** There is no authentication at all yet: callers pass a `User` object directly. `LOGIN` and `CLEARANCE_VERIFIED` events are therefore never emitted.
- **No production PKI**, no signing, no key management.
- **No external policy authority.** Policy is a local JSON file; there is no policy distribution, versioning or attestation.
- **Grants are in-memory** (`InMemoryAccessGrantRepository`) and reset on restart. A persisted implementation drops in behind `AccessGrantRepository`.
- **The audit log is append-only by application convention, not cryptographically.** The SQLite file is writable by anything with filesystem access; no hash chaining or tamper-evidence yet.
- **Masking is decided, not applied.** A PARTIAL decision names the fields to withhold; the component that serves evidence must honour it — no evidence-serving code exists yet.
- **No lint/type tooling** (ruff/mypy) is configured in the repo; validation is the test suite plus import checks.
- `SECRET_KEY` in `app/core/config.py` still has a hardcoded default. It must become a required env var with no default before authentication work lands.
- No Neo4j driver in `requirements.txt` yet — needed before `GraphRepository` gets a real implementation.

## Architecture notes carried forward

- README describes the full product vision, not current state; it was intentionally left alone.
- `app/core/security.py` (SHA-256 helpers, from the original repo) is unrelated to the `app/security/` package; it remains the natural implementation for `IntegrityProvider`.
- `docker-compose.yml` omits a frontend service because no frontend code exists yet.
