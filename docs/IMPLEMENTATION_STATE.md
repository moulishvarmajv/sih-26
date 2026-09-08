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
- Tests covering the clearance/privacy policy, the full decision matrix, and event persistence.

### Phase 3 — local authentication boundary
- **LocalIdentityProvider** (`app/security/identity/local_provider.py`): username/password verification, user lookup, disabled-account and invalid-credential rejection. An unknown username costs the same hashing work as a wrong password, so timing does not disclose which accounts exist.
- **Password hashing** (`app/security/identity/passwords.py`): stdlib scrypt behind a `PasswordHasher` protocol — no new dependency (`passlib` is listed in `requirements.txt` but is not installed). Hashes are self-describing (`scrypt$n$r$p$salt$hash`) so parameters can be raised later; verification is constant-time.
- **Local user persistence** (`app/security/identity/user_store.py`): SQLite `user_accounts` / `roles` / `user_roles`. Returns either a `UserAccount` (holds the password hash, identity-provider only) or a domain `User` (no password material) — so leaking a hash requires deliberately crossing a type boundary.
- **Authenticated sessions** (`app/security/session/`): `Session` with id, user, created/expires, status, authentication method and correlation id, behind a `SessionStore` protocol with a SQLite implementation. Only the SHA-256 of the bearer token is stored, so a copy of the database cannot be replayed. Sessions record *which* agency context is active, not the role/clearance it carries — those are re-read live, so a revoked clearance applies on the next request.
- **`POST /auth/login`**: credentials → provider → session → `LOGIN` → clearance verification → `CLEARANCE_VERIFIED` → safe response. Every failure mode collapses to one `AUTHENTICATION_FAILED` response while the real reason is audited server-side as `LOGIN_FAILED`.
- **`GET /me`**: safe authenticated projection (user, roles, live-verified clearance, authorized agencies, active context, session expiry).
- **`POST /context/switch`**: builds the requested context as a *claim* from live role/clearance, asks `SecurityService` for a decision, and writes it to the session only on ALLOW. Unknown agencies travel the same path and are denied by the grants check, so the response never discloses the agency catalogue.
- **Session boundary** (`app/api/dependencies.py`): `get_current_session` / `get_current_user` / `get_current_agency_context`. Identity is derived from the bearer token only; no route accepts a client-supplied user id.
- **Shared clearance verification** (`app/security/clearance/verification.py`): one definition of "is this grant current", used by both the authorization facts and the login flow so they cannot drift.
- **Secret management**: the hardcoded `SECRET_KEY` default is gone. It is read from the environment, required in production (startup fails without it), and generated ephemerally per process elsewhere. The CORS default no longer includes `"*"`, which would have exposed session tokens to any origin.
- **Synthetic dev identities** (`app/security/identity/seed.py`): USR-001/002/003, seeded via `python -m app.security.identity.seed` with `DEV_SEED_PASSWORD` from the environment; no credential is committed.
- **86 tests** in total, 35 of them new.

## In progress

Nothing. Phase 3 is complete and committed.

## Next — exactly one subsystem

**Evidence persistence and the first `EvidenceSource` adapter** (`app/core/evidence/`): a store for `EvidenceRecord` / `EvidenceVersion` / `ProcessingRun`, plus one adapter that emits records, wired to a protected route that enforces `authorize_evidence_access` and actually applies the masking a PARTIAL decision names. This is what turns the security pipeline from evaluated to enforced.

Do not start Neo4j ingestion, entity resolution, analytics, the navigator, the frontend, or blockchain work before that.

## Known limitations

- **Synthetic/local identities only.** Accounts are local rows created by the dev seeder; there is no user administration, password change, lockout or rotation.
- **No government identity integration and no production SSO.** `LocalIdentityProvider` is one adapter behind `IdentityProvider`; an enterprise or government provider replaces it without changes above that boundary.
- **No distributed session store.** Sessions are SQLite rows behind `SessionStore`; there is no shared session service, and no logout/revocation route (the store supports expiry marking only).
- **No production PKI**, no signing, no key management.
- **No external policy authority.** Policy is a local JSON file; there is no policy distribution, versioning or attestation.
- **Grants and the agency directory are in-memory** and reset on restart. Persisted implementations drop in behind `AccessGrantRepository` / `AgencyDirectory`.
- **Context switching picks the user's first role.** Multi-role users cannot yet choose which role a context operates under.
- **The audit log is append-only by application convention, not cryptographically.** The SQLite file is writable by anything with filesystem access; no hash chaining or tamper-evidence yet.
- **Masking is decided, not applied.** A PARTIAL decision names the fields to withhold; no evidence-serving code exists yet to honour it.
- **No lint/type tooling** (ruff/mypy) is configured in the repo; validation is the test suite plus import checks.
- No Neo4j driver in `requirements.txt` yet — needed before `GraphRepository` gets a real implementation.

## Architecture notes carried forward

- README describes the full product vision, not current state; it was intentionally left alone.
- `app/core/security.py` (SHA-256 helpers, from the original repo) is unrelated to the `app/security/` package; it remains the natural implementation for `IntegrityProvider`.
- `docker-compose.yml` omits a frontend service because no frontend code exists yet.
