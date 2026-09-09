# SHADOW-INTEL — Implementation State

_Update as phases land — do not let this drift from reality._

## Status at a glance

Four levels, used consistently below. **VERIFIED LIVE** is reserved for
behaviour exercised against the real dependency, not a fake.

| Subsystem | Status | Evidence |
|---|---|---|
| Module boundaries, typed contracts, plugin registry | IMPLEMENTED | unit tests |
| Flight Recorder event store (SQLite, append-only) | IMPLEMENTED | service tests |
| Clearance / privacy policy as data | IMPLEMENTED | unit tests |
| Authorization engine, SecurityService, agency context | IMPLEMENTED | decision-matrix + API tests |
| Local authentication, sessions, `/auth/login`, `/me`, `/context/switch` | IMPLEMENTED | API tests |
| Evidence lifecycle: VIEW / ANALYZE / REANALYZE, versions, runs, results | IMPLEMENTED | service + API tests |
| Server-side privacy masking | IMPLEMENTED | evidence, graph and resolution API tests |
| Neo4j knowledge graph: schema, idempotent ingestion, authorized read | VERIFIED LIVE | 8 integration tests against Neo4j 5 Community |
| Entity resolution: normalization, blocking, scoring, review, lineage | IMPLEMENTED | 126 unit/service/API tests |
| `INFERRED_SAME_ENTITY` projection and status restatement | VERIFIED LIVE | 9 integration tests against Neo4j 5 Community |
| Full pipeline over HTTP: auth → case → evidence → graph → resolution → review | VERIFIED LIVE | 5 end-to-end tests against Neo4j 5 Community |
| Graph analytics: connectivity, components, bridges, temporal concentration | IMPLEMENTED | 98 unit/service/API tests |
| Bounded shortest path over the authorized graph | VERIFIED LIVE | Cypher exercised against Neo4j 5 Community |
| Investigation signals with versioned history | IMPLEMENTED | service and repository tests |
| Evidence debt: seven categories, weighting policy, bands | IMPLEMENTED | 173 unit/service/API tests |
| Debt snapshots, item lifecycle and trend | IMPLEMENTED | repository and service tests |
| Debt computed over the authorized evidence scope | VERIFIED LIVE | 7 integration tests against Neo4j 5 Community |
| Graph ingestion trigger | PARTIALLY IMPLEMENTED | in-process only; no endpoint or scheduled job |
| Staleness / invalidation | PARTIALLY IMPLEMENTED | direct-only; no dependency graph |
| Multi-role context selection | PARTIALLY IMPLEMENTED | the user's first role is used |
| Grant and agency persistence | PARTIALLY IMPLEMENTED | in-memory behind the protocols; reset on restart |
| Transitive entity clustering | NOT IMPLEMENTED | — |
| Evidence Navigator | NOT IMPLEMENTED | — |
| IMEI/IMSI analytics | NOT IMPLEMENTED | — |
| Tower / spatio-temporal analytics | NOT IMPLEMENTED | — |
| Frontend | NOT IMPLEMENTED | — |
| Blockchain / integrity anchoring | NOT IMPLEMENTED | — |
| Asyncio DAG task executor | NOT IMPLEMENTED | contract only |

**708 tests**: 679 that need no external service, and 29 that need a reachable
Neo4j and skip themselves when there is none.

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

### Phase 4 — evidence lifecycle
- **Evidence domain model** (`app/core/evidence/models.py`): `EvidenceRecord` (logical item) / `EvidenceVersion` (concrete content version) / `ProcessingRun` (one execution) / `AnalysisResult` (its output), with explicit `EvidenceState`, `VersionState`, `ResultState` and `RunStatus` enums instead of scattered strings.
- **EvidenceRepository** + SQLite implementation. It owns the transitions so callers cannot forget them: a new version supersedes the previous one and makes results computed from it STALE; a new CURRENT result supersedes the previous one for that task type. Nothing is deleted or overwritten.
- **Local evidence storage**: `EvidenceObjectStore` with a filesystem implementation (`<root>/CASE/EV/v1/source.json`). Payloads live outside SQLite; versions store an opaque reference. Key parts are validated, so an identifier from a source adapter cannot escape the root.
- **CaseRepository** (`app/core/investigation/`) + SQLite implementation — a case must resolve before evidence can be authorized, since its agency and security level are authorization inputs.
- **Integrity metadata**: SHA-256 over canonically-serialised payloads (sorted keys), stored per version alongside the source reference and ingestion timestamp. Deterministic evidence ids mean re-ingesting the same source record produces a *version*, not a duplicate — and re-ingesting unchanged content produces nothing at all.
- **SyntheticCDRSource** (`app/infrastructure/sources/`): one local adapter over a controlled dataset, no network. It validates and rejects malformed rows, and preserves messy ones verbatim — duplicates, inconsistent formatting, a missing optional field, and one IMEI seen with two IMSIs. Cleaning those up would rewrite what was observed; that judgement belongs to analysis.
- **`CdrSummaryAnalyzer`**: a deterministic, versioned structural summary (counts only, no identifiers) that proves the lifecycle. Results are classified DERIVED, never OBSERVED.
- **VIEW / ANALYZE / REANALYZE** in `EvidenceService`. VIEW and `GET .../analysis` never create a run; ANALYZE reuses a CURRENT result matching the latest version; REANALYZE always creates a new run and keeps the previous result as SUPERSEDED.
- **Protected endpoints**: `GET /cases/{case_id}/evidence`, `GET /evidence/{id}`, `GET /evidence/{id}/versions`, `GET /evidence/{id}/analysis`, plus `POST /evidence/{id}/analyze` and `POST /evidence/{id}/reanalyze`. All require an authenticated session and an active agency context; unknown and unauthorized resources return the same code so neither can be enumerated.
- **Masking is now applied, not just decided.** A PARTIAL decision masks the payload server-side before it leaves the process (`+919876543210` → `+91-XXXX-3210`; IMEI/IMSI → `***`). Which fields keep a suffix and which are redacted outright is policy data (`partial_mask_fields`), not a guess from the value's shape — an IMEI and a phone number are both long digit strings.
- **Audit**: `EVIDENCE_CREATED`, `EVIDENCE_VERSION_CREATED`, `EVIDENCE_VIEWED`, `EVIDENCE_ANALYSIS_STARTED` / `_COMPLETED` / `_FAILED` / `_REUSED`, `EVIDENCE_REANALYZED`, on top of the access decisions SecurityService already records.
- **130 tests** in total, 44 of them new.

### Phase 5 — Neo4j knowledge graph foundation

**Architecture.** Neo4j Community runs locally via Docker Compose; the driver is reached only through `Neo4jGraphRepository`. Nothing above the repository sees a driver object — the boundary types are the driver-free dataclasses in `app/core/graph/models.py`. The path is: raw graph → repository → GraphService (authorization, scoping, masking, audit) → API DTOs.

**Node and relationship model.**
- Nodes: `Person`, `Phone`, `Device`, `Case`, `Evidence`. `Account` and `CellTower` are constrained in the schema but never written yet.
- Relationships: `Person-[:USES]->Phone`, `Phone-[:INSERTED_IN]->Device`, `Phone-[:CALLED]->Phone`, plus `Evidence-[:BELONGS_TO]->Case` (structural) and `<entity>-[:OBSERVED_IN]->Evidence` (node-level provenance).
- Natural keys, which every MERGE uses: `Person.person_id`, `Phone.msisdn`, `Device.imei`, `Case.case_id`, `Evidence.evidence_id`, `Account.number`, `CellTower.cgi`.

**Constraints and indexes.** A uniqueness constraint per natural key (which also provides the backing index), plus relationship indexes on `case_id` and `observation_id` for each relationship type. All DDL uses `IF NOT EXISTS`; schema initialization is idempotent and never drops or recreates anything.

**Provenance model.** Provenance lives on observations, not folded into entity nodes: `case_id`, `evidence_id`, `evidence_version_id`, `source_type`, `observed_at`, `trust_class` and `processing_run_id` are written onto each relationship. A Phone seen in three evidence versions keeps three observation edges, so lineage survives reprocessing rather than collapsing into one mutable "latest" record. Relationship writes use `ON CREATE SET` only, so a recorded observation is never rewritten.

**Idempotent ingestion.** Every relationship carries a deterministic `observation_id` = SHA-256 over the source-event data plus the evidence version id — no UUIDs. Re-processing the same version merges onto the same edge (no duplicates); a genuinely new version records a new observation. Nodes MERGE on their natural key. `Evidence-[:BELONGS_TO]->Case` is deliberately version-independent.

**Formatting vs. resolution.** `Phone.msisdn` keys on digits only, so `+91 98 1234 5678` and `919812345678` reach the same node, and the raw text as observed is kept on the observation edge. No country code is guessed. A `Person` node is created only when the source actually reports a subscriber id — deriving a person from a phone number would be entity resolution, which is not implemented.

**Authorization path.** `GET /cases/{case_id}/graph` requires an authenticated session and an active agency context. GraphService authorizes case access, then authorizes *each* evidence item in the case: evidence the reader may not see is excluded from the query scope rather than filtered out of the result, and a PARTIAL decision masks graph identifiers (`Phone.msisdn`, `Device.imei`, `imsi`, raw values) using the same privacy policy that masks the evidence view. Node ids in responses are hashed, so a masked node still has a distinct, usable identity. Unknown and unauthorized cases return the same code.

**Availability.** The driver is imported lazily, so the application imports, starts and serves every non-graph route when the `neo4j` package or server is absent — verified with the package blocked. Only graph operations fail, with `GRAPH_UNAVAILABLE` (503).

**Audit.** `GRAPH_INGESTION_STARTED` / `_COMPLETED` / `_FAILED`, `GRAPH_QUERY_EXECUTED`, `GRAPH_ACCESS_ALLOWED`, `GRAPH_ACCESS_DENIED` — all through the existing EventStore, with correlation ids taken from the authorization decision.

**Tests.** 174 passing (44 new), plus 8 Neo4j integration tests that skip unless a server is reachable.

### Phase 6 — deterministic entity resolution

**What it decides.** Whether two *observations* of an entity, seen in different
evidence, denote the same real-world entity. It never rewrites what was
observed: an accepted resolution adds an `INFERRED` link beside the `OBSERVED`
facts, and both stay readable and distinguishable. Resolution is an explicit
processing step — it is not reachable from evidence ingestion or graph
persistence, and reading a case's resolutions never computes any.

Only `PERSON` entities are resolved. Identifiers (phone, IMEI, account) are
matching *signals*; the entity being resolved is the person a source named.

**Architecture.** One direction of dependency, mirroring the evidence and graph
planes:

```
EntityResolutionService          authorization, orchestration, review, audit
  -> ResolutionPolicy / Scorer   weights, thresholds, deterministic scoring
  -> ResolutionRepository        decisions, candidates, reviews, lineage
  -> GraphRepository             the inferred link only
       -> Neo4j
```

`Neo4jGraphRepository` gained no matching logic; the service never sees a driver
object. Extraction and projection sit beside the graph mapper as the pieces that
know what a source means (`app/core/resolution/`).

**Normalization** (`app/core/normalization.py`, shared with graph mapping so the
two cannot drift). Formatting only: `+91 98765 43210` and `919876543210`
canonicalise to the same digits, so they compare equal — but a number without a
country code stays a *different* value than one with it, because assuming a
country would be an inference. Identifiers collapse to upper-case alphanumerics,
names and addresses to sorted lower-case tokens (so word order does not change
identity), and similarity is `difflib.SequenceMatcher` over those canonical
forms — stdlib, deterministic, no model. Every observation keeps
`raw_attributes` alongside the canonical ones, so normalization never destroys
provenance. Unusable values raise rather than being guessed at.

**Candidate generation** (`candidates.py`). Deterministic blocking, never an
all-pairs comparison: observations are indexed by a canonical key and only
observations in the same block are compared. Five strategies, listed in policy:
`EXACT_PHONE`, `EXACT_IMEI`, `EXACT_ACCOUNT`, `SOURCE_IDENTIFIER` (an entity's
own key and any cross-source reference it quotes), and `NAME_LOCALITY`. The last
blocks on *every* name token paired with the locality rather than on a
positional surname, which would assume a name ordering that does not hold
everywhere. Every candidate records the strategy and key it blocked on, so "why
was this pair compared?" is answerable without re-running anything. Generating a
candidate asserts nothing and writes nothing to the graph; two observations of
the *same* entity key are not a candidate at all, since the source already said
they are one entity.

**Scoring** (`scoring.py`). Pure — a function of (policy, two observations), with
no storage, clock or randomness. Two numbers come out and both matter:

```
score            = (earned contributions - conflict penalties) / comparable weight
evidence_weight  = sum of the weights of the signals that were comparable
```

Dividing by the *comparable* weight means a source that simply does not carry an
address is not punished for it; reporting the comparable weight separately means
a pair agreeing on one weak attribute cannot masquerade as a pair agreeing on
six strong ones. Each of the nine signals returns `AGREED`, `DISAGREED` or
`NOT_COMPARABLE` with its weight and earned contribution, so the arithmetic is
inspectable line by line. Conflicts are disagreements the policy names
explicitly; they subtract, and some block auto-acceptance however high the
score. A blocking conflict is decided on the *unpenalised* agreement, because
the penalty exists to stop an automatic merge, not to hide the pair — one number
registered to two different identity references is exactly what an investigator
needs to see.

Recommendations use identity vocabulary only: `MATCH`, `POSSIBLE_MATCH`,
`REVIEW_REQUIRED`, `CONFLICT`, `UNRESOLVED`. Nothing in the subsystem describes
conduct, and a test asserts the vocabulary stays that way.

**Policy configuration** (`app/core/resolution/resolution_policy.json`, path from
`RESOLUTION_POLICY_PATH`). Every weight, threshold and rule is data, keyed by
entity type; no number is compared in code. There is deliberately no single
universal threshold — four work together:

| threshold | what it guards |
|---|---|
| `auto_accept` (0.80) | a score at or above this may be asserted without a human |
| `review_floor` (0.45) | below this the pair is recorded and nothing is asserted |
| `minimum_evidence_weight` (0.45) | how much had to be *comparable* before auto-accepting |
| `ambiguity_margin` (0.05) | how close a rival candidate may be before both go to review |

Signal weights sum to 1.0 (phone 0.30, source identifier 0.20, account 0.15,
IMEI 0.10, name 0.10, address 0.05, temporal 0.05, source reliability 0.03,
cross-source 0.02). Conflict rules carry a penalty and a `blocks_auto_accept`
flag; source reliability is per-source data with a fail-low default for unknown
sources. Confidence bands come from policy, and a decision stores the band's
lower bound alongside the label, so confidence is never an unexplained number.

**Human review.** Ambiguity goes to a person: when two candidates for the same
observation score within the margin, neither is accepted, both are recorded with
`AMBIGUOUS_ALTERNATIVE`, and the proposal becomes `REVIEW_REQUIRED` — picking
the higher of 0.91 and 0.89 would be an arbitrary tie-break presented as a
conclusion. `POST .../approve`, `.../reject` and `.../defer` record a reviewer,
timestamp, action and optional reason; deferral deliberately leaves the
resolution open so it stays in the queue. Reviews are append-only and survive
supersession of the decision itself. Automated and human outcomes stay
distinguishable forever through `decision_actor` (`SYSTEM` / `HUMAN`), and only
an open decision can be closed — an auto-accepted or already-decided resolution
cannot be re-decided in place.

**Inferred graph relationships.** An accepted decision projects one
`(:Person)-[:INFERRED_SAME_ENTITY]->(:Person)` edge carrying `resolution_id`,
`lineage_id`, `resolution_version`, `status`, `trust_class: "INFERRED"`, score,
confidence, evidence weight, `policy_version`, the supporting signal names, the
conflict rules, *both* source evidence ids and version ids, and who decided.
Direction is fixed by sorting the two entity keys and the edge's
`observation_id` derives from the resolution id, so re-projecting is idempotent.
Observed relationships are untouched: they remain `ON CREATE SET` only, and a
test asserts every observation's properties are byte-identical after a
resolution run. `update_inferred_link_status` is the one mutation the graph
interface permits and its Cypher `MATCH` is scoped to `INFERRED_SAME_ENTITY`, so
it cannot reach an observation however it is called — a rejected or superseded
inference has its status restated, never deleted.

An inferred link is derived from *two* evidence items, so the evidence-scoped
`GET /cases/{id}/graph` cannot authorize it: `fetch_case_graph` excludes it by
type and it is served instead by the entity-resolution API, which authorizes
both sides.

**Version lineage.** A lineage id identifies "this pair of entities in this
case", order-independently. Each decision carries a `resolution_version`, the
`policy_version` it was computed under, both evidence-version references, and an
`input_fingerprint` over (both observation ids + policy version). Re-running with
an unchanged fingerprint is a no-op; a changed one supersedes the previous
decision (status `SUPERSEDED`, linked forward by `superseded_by`) and records a
new version, with the old one still readable. A resolution a person *rejected* is
never re-accepted automatically: the new version carries `PRIOR_HUMAN_REJECTION`
and goes back to review. This is lineage only — the full dependency/staleness
engine is still not built.

**API.** All under an authenticated session with an active agency context:

- `POST /cases/{case_id}/entity-resolution/run`
- `GET /cases/{case_id}/entity-resolution` (optional `status_filter`)
- `GET /cases/{case_id}/entity-resolution/{resolution_id}`
- `POST /cases/{case_id}/entity-resolution/{resolution_id}/approve`
- `POST /cases/{case_id}/entity-resolution/{resolution_id}/reject`
- `POST /cases/{case_id}/entity-resolution/{resolution_id}/defer`

Responses are machine-readable DTOs, not prose: `recommendation`, `score`,
`evidence_weight`, `confidence` + `confidence_floor`, `policy_version`, reason
codes, per-signal evidence, and conflicts with their rule and penalty. `GET`
never resolves anything; running is an explicit `POST`.

**Security boundary.** Authorization is per *evidence item* and happens before
anything is read: a resolution is derived from two evidence items, so evidence
the reader may not see never enters extraction, and a resolution is readable only
when *both* its evidence items are. Running requires `RUN_ENTITY_RESOLUTION`,
reading `VIEW_ENTITY_RESOLUTION`, and deciding `REVIEW_ENTITY_RESOLUTION` — the
analyst role deliberately lacks the last. Unknown cases, unauthorized cases and
unknown resolution ids all return the same code, so none can be enumerated.

Matching material never leaves the process. Attribute *values* are not returned
at any clearance level — the explanation names the attribute a signal compared
and reports numbers, and a candidate reports the attribute it blocked on rather
than the phone number it blocked on. Entity labels are masked through the
existing privacy policy when the reader's evidence decision was PARTIAL, and a
masked entity keeps a usable identity through a hashed `entity_ref`, exactly as
graph node ids do. An API test asserts no raw identifier from the synthetic data
appears anywhere in a partial reader's response.

**Audit.** Through the existing EventStore, with the acting user, case and the
correlation id from the authorization decision: `ENTITY_RESOLUTION_STARTED`,
`_CANDIDATE_CREATED`, `_AUTO_ACCEPTED`, `_REVIEW_REQUIRED`, `_UNRESOLVED`,
`_COMPLETED`, `_APPROVED`, `_REJECTED`, `_DEFERRED`, `_SUPERSEDED`,
`_PROJECTED`, `_FAILED`, `_ACCESS_DENIED`. Payloads carry reason codes, scores
and policy versions — never a resource value.

**Test data.** A second local source, `SyntheticSubscriberRegisterSource`
(`synthetic_subscriber_sample.json`), because a CDR carries no names or
addresses to compare. Its records are ordinary registration entries whose
identifiers overlap the way real ones do; nothing in the data describes conduct.
Together with the existing CDR export they cover:

| | scenario | outcome |
|---|---|---|
| A | one subscriber across a CDR export and a register | `AUTO_ACCEPTED` |
| B | `+919876543210` vs `+91 98765 43210` | matches on the canonical phone |
| C | phone + IMEI + operator reference + consistent window | score 0.988, HIGH |
| D | two register entries on one household number | both `REVIEW_REQUIRED` |
| E | a reassigned number with two identity references | `CONFLICT`, no merge |
| F | similar names in one city, nothing else shared | `UNRESOLVED`, separate |
| G | re-running over unchanged evidence | every decision unchanged |
| H | a new register export | new candidate, earlier decisions kept |

**Zero external spend.** Deterministic Python and the standard library. No LLM
call, no paid AI service, no new runtime dependency, and no queue or scheduler.

**Tests.** 308 passing at the close of Phase 6, 126 of them new, covering normalization determinism,
blocking, exact and multi-signal matching, confidence derivation, ambiguity
routing, conflict detection, absence of silent merges, INFERRED vs OBSERVED
labelling, retained supporting evidence and policy version, approve/reject/defer,
role and case isolation, unauthorized access, idempotency, preserved history and
emitted events. 9 of them are Neo4j integration tests for the inferred-link
Cypher, alongside the 8 from Phase 5; all 17 pass against a real Neo4j 5
Community container, and the suite skips them and stays green with no server
reachable. The integration path earned its keep immediately: it caught the
relationship reader stripping `trust_class` off inferred links, which the
in-memory fake could not see.

**Phase 6 limitations.**

- **No transitive clustering.** Resolution decides pairs. If A matches B and B
  matches C, nothing concludes A matches C, and there is no entity cluster or
  canonical-record concept.
- **PERSON only.** The policy is keyed by entity type and the projection has a
  label map, but no other entity type is resolved.
- **Subscriber-register evidence has no graph mapping.** It participates fully in
  resolution; `GraphService` counts it as skipped during ingestion rather than
  guessing a projection for it. Person nodes an inferred link needs are merged on
  their natural key by the projection itself.
- **Inferred links are absent from the case-graph endpoint.** Serving them there
  needs two-sided evidence authorization in the graph query; until then they are
  read through the resolution API.
- **Similarity is a string ratio,** not a phonetic or transliteration-aware
  comparison. Two spellings of one name across scripts will not match.
- **Resolution runs synchronously** inside the request, like analysis. Candidate
  generation is blocked rather than quadratic, but nothing is batched or
  backgrounded.
- **Recomputation is whole-case.** A run re-extracts and re-scores everything for
  the case; there is no incremental "only what changed" path.
- **The review queue has no assignment, priority or SLA,** and no notification —
  `REVIEW_REQUIRED` is a status, not a workflow.

### Phase 6.5 — engineering hardening

No new capability. An audit pass over what Phases 1-6 left behind, so the next
phase starts from a foundation that is verified rather than assumed.

**Configuration defects found and fixed.** `.env.example` had drifted from the
code in two ways, and following its own instructions broke startup:

- `CLEARANCE_POLICY_PATH` was `security/policy/clearance_policy.json`, missing
  the `app/` prefix. Copying the file to `.env` made security-policy loading
  fail at startup.
- `DEV_SEED_PASSWORD` was documented as a `.env` key, but it is not a setting —
  and settings reject unknown keys. Setting it as the file instructed produced
  `ValidationError: Extra inputs are not permitted`.

The file now documents exactly the settings that exist, `DEV_SEED_PASSWORD` is
described as the process-environment variable it actually is, and
`tests/test_config_secrets.py` loads the example file, resolves both policy
paths from it, and asserts every key in it is a real setting. `extra="forbid"`
is now explicit and documented rather than an inherited default: a typo in
`NEO4J_PASSWORD` should stop startup, not silently fall back.

**Dead configuration removed.** `API_V1_STR`, `JWT_ALGORITHM`,
`JWT_ACCESS_TOKEN_EXPIRE_MINUTES`, `BLOCKCHAIN_NETWORK`, `ENABLE_MOCK_LEDGER`,
`DATA_DIR` and `ENABLED_PLUGINS` were read by nothing. A knob that looks
configurable but is never consulted invites someone to change it and conclude
the system ignored them. A test now asserts every remaining setting appears
somewhere outside `config.py`.

**Pydantic deprecation cleared.** Class-based `Config` became
`model_config = SettingsConfigDict(...)`. Behaviour is unchanged and the
configuration tests cover it; the suite now emits no warning from our own code.

**Dependencies trimmed.** `requirements.txt` installed `pandas`, `polars`,
`numpy`, `scikit-learn`, `web3`, `pycryptodome`, `python-jose`, `passlib`,
`requests`, `aiofiles` and `python-multipart` — none of which anything imports,
and most of which were not installed in working environments at all. It now
lists what the application imports; `requirements-dev.txt` carries `pytest` and
`httpx`, so the container image no longer ships test tooling. Later phases add
back what they actually need.

**Test isolation defect found and fixed.** The Neo4j integration teardown
deleted orphan nodes by a global sweep (`every orphan node with an msisdn`),
which both reached outside the run and *missed* `Evidence` nodes entirely — 40
orphans had accumulated in the local database across earlier runs. Cleanup is
now precise: `tests/neo4j_support.py` records the nodes a run writes and deletes
exactly those keys when they are left unreferenced, with relationships scoped by
the run's unique case id. Verified: node count is identical before and after a
full integration run.

**Test infrastructure.** The three API suites had each copied the same ~60 lines
of composition; `tests/api_harness.py` now wires the real stack once and each
suite states only its own scenario. `pytest.ini` registers an `integration`
marker, so a run can be scoped (`-m "not integration"`) rather than filtered by
filename, and skips can be attributed. `test_smoke` reset a hardcoded list of
cached providers that had already gone stale — it uses `reset_providers()`, and
a new test asserts that function covers every cached provider.

**Security regression audit.** `tests/test_security_regression.py` enumerates
routes from the running application rather than from a hand-maintained list, so
a route added later is covered the moment it exists. It asserts that every
protected route refuses an anonymous caller and a forged token, that every
case-scoped route requires an active agency context, that a reader in another
agency cannot reach the case, that a revoked grant applies on the next request,
that no error body carries evidence content, that login failure modes are
indistinguishable, and that masking is applied server-side. It introduces no
authorization concept — it pins down what Phases 2-6 already implement.

**API contract.** Error responses now carry a documented schema
(`ErrorResponse`), so a client is not guessing the `{"detail": {"error": ...}}`
shape: every protected route documents 401/403, and the routes that can answer
404, 409 or 503 document those too. `status_filter` on the resolution listing is
typed as the enum, so an unknown value is a 422 about the request rather than
`RESOLUTION_ACCESS_DENIED` — reporting a typo as a security outcome made both
harder to read. One inconsistency is documented rather than changed: the
`/evidence/...` routes take `case_id` as a query parameter while every other
case-scoped route takes it in the path. Changing that is an API break, not
hardening.

**Docker.** The backend service gained a `/health` healthcheck using the stdlib
(the image has no curl), and `SECRET_KEY`/`LOG_LEVEL` passthrough — without the
former a production container would fail startup with no way to supply one.
Neo4j's own configuration was left alone: verified healthy, zero restarts, with
data persisting in named volumes across restarts and rebuilds.

**Documentation.** `docs/DEVELOPMENT.md` covers setup, the Neo4j lifecycle,
seeding, running the API, the four test categories and the failure modes worth
recognising. No task runner or wrapper scripts were added: every workflow is a
single command, and a script would only be another layer to keep in sync.

**Suite runtime, investigated.** The suite went from ~22s (308 tests) to ~34s
(387 tests), and one-off readings as high as 85s prompted a check for a
regression. There is none. An identical, unmodified test file runs at 1.25-1.36s
in both the pre- and post-hardening trees, so per-test cost did not change; the
high readings came from a concurrent test run competing for the machine. The
increase is the 79 added tests, which are disproportionately API and integration
tests — the most expensive kind, because each builds four SQLite databases. The
hotspot is SQLite file creation at ~15ms per database, not password hashing at
2.1ms for three.

Sharing one harness across a module was tried and reverted: it saves about ten
seconds but produced cumulative interference between cases, since the sweeps and
the state-changing tests contend over one global `dependency_overrides`.
Isolation is what these suites exist to protect, so it was not traded for the
ten seconds. Sixty sequential logins against one harness were checked first, to
confirm the interference was a fixture artefact and not a defect in session
handling; all sixty succeeded.

**Not changed, deliberately.** No exception architecture redesign, no new
endpoints, no dataset expansion, no authorization concepts, and no change to the
module boundaries. `/ready` still does not probe Neo4j — the application is
designed to serve every non-graph route with the graph down, so a readiness
check that failed on an unreachable Neo4j would report a working process
unhealthy, and would put a connection timeout on an endpoint orchestrators poll.

### Phase 7A — graph analytics and investigation signals

**What a signal is, and is not.** A signal is an observation about the *shape*
of a case graph: which entities sit between otherwise separate groups, which are
unusually well connected, which observations cluster in time. It is a place to
look. There is no signal type, reason code or field in the model that describes
a person's conduct, and a test asserts the vocabulary stays that way. A busy
number is usually a busy number; the system says where the graph is dense and
leaves the meaning to whoever reads the evidence.

**Architecture.**

```
GraphAnalyticsService     authorization, orchestration, signals, audit
  -> AnalysableGraph      the authorized, masked view — the only thing metrics see
  -> metrics              pure, deterministic: degree, components, bridges, temporal
  -> AnalyticsRepository  runs and signals, with history
  -> GraphRepository      one query: the bounded shortest path
       -> Neo4j
```

`Neo4jGraphRepository` gained no analytic logic. The service never receives a
driver object, and the metrics never receive a `GraphSnapshot`.

**Supported analytics.**

| analytic | what it answers | where it runs |
|---|---|---|
| connectivity | degree, in/out-degree, distinct neighbours, rank within the case | service, over the authorized view |
| connected components | how the case graph divides into groups, with type composition | service, union-find |
| bridges | which entities hold otherwise separate groups together | service, articulation points |
| temporal concentration | which windows carry unusually many observed events | service, fixed windows |
| shortest path | the shortest observed walk between two entities | repository, one bounded Cypher query |

Path finding is the one analytic pushed into the database, because the database
can answer it without anyone loading the graph; a bounded `shortestPath` is one
query where fetching the subgraph would scale with the case rather than with the
answer. Everything structural is computed above the repository, over *one*
authorized view, so two metrics can never disagree about the graph they
described.

**Why articulation points rather than betweenness centrality.** Betweenness
yields a number. An articulation point yields a statement an investigator can
check: *without this entity, these groups have no connection in the authorized
graph*. Every signal in this phase has to be explainable, and a threshold on a
centrality score is not an explanation. The signal reports how many regions the
entity separates and how large each is.

**What counts as a connection.** Analytics sees entities — Person, Phone,
Device, and the Account and CellTower labels reserved for later — joined by
`USES`, `INSERTED_IN` and `CALLED`. `Case` and `Evidence` nodes and their
`OBSERVED_IN` / `BELONGS_TO` edges are provenance, not structure: two phones are
not connected because they appeared in the same export. Including them made the
export the densest node in every case and joined every group through it, which
is an artefact an investigator would have to learn to ignore. Provenance is not
lost — every relationship still names the evidence it came from.

**Signal taxonomy.** `HIGH_CONNECTIVITY`, `CROSS_DOMAIN_BRIDGE`,
`COMPONENT_STRUCTURE`, `TEMPORAL_CONCENTRATION`, `SHORTEST_PATH`. Reason codes
are machine-stable and rendered by a client, never parsed as prose:
`DEGREE_ABOVE_THRESHOLD`, `TOP_RANKED_CONNECTIVITY`, `REMOVAL_SEPARATES_GRAPH`,
`CONNECTS_SEPARATE_GROUPS`, `SPANS_MULTIPLE_ENTITY_TYPES`,
`RESTS_ON_SINGLE_WEAK_RELATIONSHIP`, `EVENTS_CONCENTRATED_IN_WINDOW`,
`COMPONENT_IS_ISOLATED`, `PATH_FOUND`, `NO_PATH_WITHIN_LIMIT`.

**Ranking, and what stops it being a hidden score.** A score is the sum of
weighted contributions and never appears without them. Every metric carries its
raw value, the policy saturation point that mapped it into [0, 1], the weight
applied, and the resulting contribution — so "why did this rank first?" is
answerable from the stored record alone. There is no universal score across
signal types: each type is ranked against its own kind, and component structure
is descriptive rather than ranked at all.

The bridge ranking is worth naming, because the obvious version is wrong.
Ranking by *how many* groups an entity separates puts a hub with four hangers-on
above a phone holding two real groups apart. Ranking accounts for the largest
region actually cut off, so the phone that is the sole link between two
neighbourhood groups outranks one that merely has a leaf attached.

**Policy as data** (`app/core/analytics/analytics_policy.json`, path from
`ANALYTICS_POLICY_PATH`). Every weight, threshold, window and limit, with the
`analytics_version` travelling on every result. Nothing in the metrics or the
service compares a hard-coded number. Normalization is policy too: combining a
degree with a count of entity types means mapping both into [0, 1] first, and
the saturation points that do the mapping are exactly the judgement that should
be visible rather than buried in an expression.

**Temporal analysis.** Fixed windows (3600s by default), anchored at the
earliest event in the authorized graph so the buckets depend on the data rather
than on when the analysis ran. A window is a concentration when it holds at
least `minimum_events_in_window` events *and* at least
`concentration_multiple` times the mean over occupied windows. The baseline is
occupied windows rather than the whole span, because one busy afternoon inside a
quiet year would otherwise mark every window as a concentration — which says
more about the span than the activity.

An undated relationship is not a dated event. Where a source recorded no time,
the relationship is excluded from temporal analysis rather than being given the
ingestion timestamp, which would cluster every undated edge into a burst that
never happened.

**Authorization, which is structural rather than remembered.** The flow is:

```
raw graph -> case scope -> evidence authorization -> privacy -> view -> signal
```

Analytics asks GraphService for the authorized, masked graph *this reader* may
see and computes from that alone. A reader who may not see an evidence item does
not get signals computed from it and then filtered — those observations were
never in scope, so the entities they would have introduced do not exist as far
as the metrics are concerned. The `AnalysableGraph` type carries no natural key
at all: an entity is a hashed id, a label the privacy policy already passed, and
a type. A restricted identifier cannot leak through a forgotten code path
because there is no code path where analytics holds one.

Two consequences that look like defects and are not: **two readers legitimately
get different answers**, because degree is degree within the authorized graph;
and **a read computes but never persists** — overview, entity and path create no
run and no signal, for the same reason viewing evidence never starts a
processing run. Recording signals is an explicit `POST`.

Path finding resolves a hashed entity id back to a natural key only inside the
authorized view, so a caller cannot ask about an entity they cannot see: there
is nothing to resolve the id against. A path that would leave the reader's scope
is reported as no path rather than as a walk with a hole in it, and an entity
that is absent answers identically to one that is out of scope.

Roles: `VIEW_ANALYTICS` to read, `RUN_ANALYTICS` to record signals. The analyst
role deliberately holds the first and not the second.

**Bounds.** `max_path_length` (6) with a hard repository ceiling of 10 that a
misconfigured policy cannot exceed; `max_relationships` (20000) beyond which a
view is analysed over the deterministic first N and flagged `truncated` on every
result that depends on it; `max_signals_per_type`; `max_component_members`.
Every query is case-scoped and parameterised — the two values Cypher cannot
parameterise, the traversal bound and the relationship type, are a clamped
integer and an enum value.

**Versioning.** Every run records its `analytics_version`, the evidence scope it
saw, who ran it and when. A signal's identity is stable across runs, so a
re-run recognises what it already produced: it supersedes the previous record
and keeps it, rather than accumulating duplicates that look like new findings.
`list_signal_history` returns every version.

**Audit.** `ANALYTICS_STARTED`, `ANALYTICS_COMPLETED`, `ANALYTICS_FAILED`,
`ANALYTICS_ACCESS_DENIED`, `SIGNAL_CREATED`, `SIGNAL_REVISED` — through the
existing EventStore, with the acting user, case and correlation id. Payloads
carry reason codes, scores and versions, never a resource value.

**API.** All authenticated, case-scoped and context-enforced:

- `GET /cases/{case_id}/analytics/overview`
- `GET /cases/{case_id}/analytics/entity/{entity_id}`
- `GET /cases/{case_id}/analytics/path/{source_id}/{target_id}`
- `POST /cases/{case_id}/analytics/run`
- `GET /cases/{case_id}/signals` (optional `signal_type`)
- `GET /cases/{case_id}/signals/{signal_id}`

**Synthetic data.** CASE-003, a separate case so Phase 5 and 6 expectations are
untouched. Group A and group B are joined only through one phone; a helpline is
reached by four unrelated callers and connects to nothing else; a single
zero-second call links a number that appears nowhere else; eight calls fall
inside one hour against otherwise spread-out contact; and a second export at L3
contains a phone that appears in no other evidence. Nothing in the data
describes conduct. The CDR source now honours a per-export `security_level`,
because analytics has to be provable against evidence a given reader cannot see.

**Tests.** 511 passing, 124 new: metrics against graphs whose answers are known
by hand (path, triangle, star, bowtie, two-triangles, chain, disconnected),
ranking, components, bridge detection with its weak-connection caveat, temporal
concentration, determinism, explainability, provenance and version retention,
case isolation, role and clearance behaviour, the API surface, and the
EventStore. 22 integration tests run against Neo4j 5 Community, including the
Cypher path query and its scoping predicate — which only a real server can
prove, since the in-memory fake walks the graph in Python.

**The mandatory security test.** CASE-003 contains an authorized entity, a
restricted entity and a relationship between them. A reader without clearance
for the restricted evidence finds no trace of that entity: not in components,
not in connectivity, not in bridges, not as a value anywhere in the payload;
asking for it directly answers exactly as an absent entity does; and a path
cannot be routed through it. The cleared reader sees it, which is what makes the
absence meaningful.

**Phase 7A limitations.**

- **Analytics are recomputed per request.** Nothing is cached; each call
  rebuilds the authorized view. Correct and simple at case scale, and the place
  to look first if a case ever gets large.
- **The authorized view is materialised in memory.** Bounded by
  `max_relationships` and flagged when truncated, but a case beyond that bound is
  analysed over a prefix rather than in full.
- **Bridges are articulation points**, so an entity with any leaf attached
  qualifies. Ranking and the weak-relationship caveat separate the interesting
  cases from the trivial ones; a threshold on region size would be a policy
  change, not a code change.
- **Paths traverse observed relationships only.** Inferred `INFERRED_SAME_ENTITY`
  links are excluded, consistent with Phase 6: they are derived from two evidence
  items and an evidence-scoped read cannot authorize them.
- **Temporal analysis is fixed-window counting.** No seasonality, no baselines
  per entity, no change-point detection, and no forecasting.
- **Masked labels can collide.** Two numbers ending in the same four digits mask
  to the same string; `entity_id` keeps them distinct, and a client should key on
  it rather than on the label.
- **No cross-case analytics.** Every query is scoped to one case by construction.

### Phase 7B — evidence debt

**What debt is, and is not.** Evidence Debt measures how much of what the
investigation currently *knows* rests on evidence that is unresolved, weak,
conflicting, missing, stale, or waiting on a person. It is a quality metric over
the investigation, and the model is worded so that it cannot be read as anything
else: there is no category, reason code, band or field that describes a person,
and a test asserts the vocabulary stays that way.

It is not guilt, not a probability of criminality or conviction, not case
completion, and not a measure of an investigator. A case can be legally strong
and carry HIGH debt; a case with no debt at all can be worthless. HIGH means the
investigation has support gaps, and names them.

**No single opaque number.** Five things are kept apart and reported separately,
because collapsing them is exactly how a "72% complete" figure gets built:
execution progress belongs to the evidence lifecycle, evidence coverage and
resolution coverage to their own subsystems, human review to the review queue,
and debt to this one. Within debt, every category is reported with its own item
count and weighted contribution, and every item carries the four factors it was
built from. The normalized [0, 1] score and the band exist for display; the raw
total and the breakdown are always available beside them.

**Architecture.**

```
EvidenceDebtService        authorization, view assembly, weighting, audit
  -> CaseDebtView          the authorized, value-free view — all a detector sees
  -> detectors             pure, deterministic: seven categories
  -> EvidenceDebtPolicy    weights, severities, expectations, thresholds
  -> EvidenceDebtRepository  snapshots and items, with history
       -> evidence / resolution / analytics repositories (read only)
```

`Neo4jGraphRepository` gained nothing. The debt engine never receives a driver
object, never runs a graph query of its own, and never re-derives what another
subsystem already decided: entity resolution stays authoritative for identity,
the evidence lifecycle for versions and results, analytics for findings. Debt
observes what those systems recorded about themselves and names the gaps.

**Debt categories.** Seven, with no catch-all:

| category | what it means | where the fact comes from |
|---|---|---|
| `UNRESOLVED` | a pair was compared and nothing was concluded | a `CANDIDATE` resolution, below the review floor |
| `HUMAN_REVIEW` | a decision is waiting on a person | a `REVIEW_REQUIRED` resolution, with or without a deferral |
| `CONFLICTING` | evidence disagrees on a material attribute | a resolution's recorded conflicts; a disagreement metric an analyzer already reported |
| `WEAK` | reasoning rests on evidence below the trust floor | `classification` INFERRED/GENERATED, *and* relied upon |
| `MISSING` | corroboration the policy expects is absent | a configured expectation whose trigger source is present |
| `STALE` | a result was computed from a superseded version | `ResultState.STALE` with nothing recomputed for the current version |
| `UNSUPPORTED_FINDING` | a recorded finding's support is incomplete | a signal citing evidence that is itself in debt |

An open decision produces **exactly one** item, never two. A `REVIEW_REQUIRED`
resolution is both an open identity question and an open piece of work; counting
it under both categories would double a case's debt for a single gap, so the
category is the one that says what has to happen — a person has to look.

Two negatives are as load-bearing as the positives. An `INFERRED` fact is *not*
automatically bad evidence: it becomes debt only when the case's recorded
reasoning rests on it, which the view answers by asking whether a finding cites
it or an accepted identity link was derived from it. And a *rejected* resolution
is not a conflict: a person concluded the two observations denote different
entities, so the disagreement was the right answer rather than an unexplained
one.

**Expectations are configuration, not judgement.** "This case is missing a
subscriber register" is a statement about how a deployment investigates, not
about evidence, so `MISSING` fires only from explicit policy entries and only
when the entry's trigger source is actually present. A case with no CDR evidence
is not missing a CDR summary. Two shapes are supported: a source the case should
carry (`SOURCE_PRESENT`) and an analysis its evidence should have
(`ANALYSIS_PRESENT`). The shipped policy carries three, one of which —
`EXPECT_DEVICE_REGISTRY` — is corroboration this platform has no adapter for at
all, which is precisely the kind of gap the metric exists to name rather than
hide.

Where staleness and a missing analysis would both describe the same evidence,
only staleness is reported: the analysis is not absent, it is out of date, and
one thing to fix should not appear as two.

**Weighting policy** (`app/core/debt/debt_policy.json`, path from
`DEBT_POLICY_PATH`). Every weight, severity multiplier, saturation point,
expectation and band threshold is data; nothing in the detectors or the service
compares a hard-coded number. One contribution is:

```
category_weight x severity_multiplier x scope_factor x criticality_factor
```

- **category weight** — how much this kind of gap matters (CONFLICTING 1.0 down
  to WEAK 0.6).
- **severity** — LOW 0.5 to CRITICAL 2.0, chosen per item by the detector from
  policy: a blocking conflict outweighs a non-blocking one, an unreviewed
  decision outweighs a deferred one.
- **scope factor** — how much of the case the gap touches, mapped into [0, 1] by
  a saturation point, with a floor so a single-item gap still counts.
- **criticality factor** — whether the affected evidence is something the case's
  reasoning actually rests on, which is the same "cited by a finding or an
  accepted link" test the weak detector uses.

Every item stores all four factors, the raw affected-scope count and the
product, so "why did this rank first?" and "why is this case HIGH?" are both
answerable from the stored record alone. The case total is the sum of the
contributions; `normalized = min(1, total / saturates_at)`; the band comes from
ordered thresholds (LOW / MODERATE / HIGH / CRITICAL). No number in the response
appears without its inputs.

**Snapshots, versions and trend.** A snapshot records the total, the normalized
score, the band, the item count, the full per-category breakdown, the top items
*serialised in full*, the ids of every item, the evidence scope, the policy
version and the engine version. Snapshots are append-only; a recalculation adds
one and never edits an earlier one. `EvidenceDebtItem` carries the engine version
alongside the policy version deliberately — a number is only explainable if you
know which rules *and* which weights produced it.

A change block accompanies every response: the previous snapshot's id and total,
the delta, which debt ids were resolved, which were newly introduced, and how
many are unchanged.

**Idempotency.** A debt item's identity is a fingerprint of what it is *about* —
case, category, subject type, subject reference and any discriminator such as a
conflict rule name — and contains no timestamp, run id or ordering. Its facts
have a second fingerprint over the assertion itself. So a recalculation over
unchanged investigation state produces the same ids, the same totals and the
same breakdown, writes no new item version, and emits no creation event. A
changed fact writes a new version and keeps the previous one.

**Lifecycle.** `OPEN` → `ACKNOWLEDGED` (a person accepts that the gap stands) →
`RESOLVED` (a recalculation no longer detects it), with `SUPERSEDED` marking the
older versions of an item whose facts changed. Nothing is deleted. An
acknowledgement survives recalculation while the item's facts are unchanged, so
automation never quietly undoes an investigator's judgement; when the facts do
change the new version starts OPEN and the acknowledged version is kept, so the
history stays readable either way.

**Authorization, which is structural rather than remembered.** The flow is:

```
raw investigation state -> case scope -> per-evidence authorization
                        -> privacy -> authorized view -> detection -> snapshot
```

A detector never receives a repository, an object store, an `EvidenceRecord` or a
payload. It receives a `CaseDebtView` assembled from already-authorized state,
and that type carries no resource value at all: an entity is the hashed
`entity_ref` resolution and the graph already publish, an attribute is its name,
a conflict is a rule name. Evidence a reader may not see never enters the view,
so the gaps it would have created do not exist as far as the detectors are
concerned — there is no item, no count, no category and no fraction of a total.
Two derived rules mirror what the owning subsystems already do: a resolution is
in scope only when *both* its evidence items are, and a finding only when *every*
evidence item it cites is.

Three consequences that look like defects and are not. **Two readers legitimately
get different totals**, because debt is debt within the authorized scope.
**A read computes but never persists** — `GET` recalculates and writes nothing,
for the same reason viewing evidence never starts a processing run. And **a
persisted record belongs to the scope it was computed in**: snapshots and items
are keyed on a fingerprint of the authorized evidence scope, so a narrow reader
can never read a cleared reader's numbers, compare a trend against them, or close
a gap they cannot see.

Roles: `VIEW_EVIDENCE_DEBT` to read, `RECALCULATE_EVIDENCE_DEBT` to record,
`ACKNOWLEDGE_EVIDENCE_DEBT` to sign a gap off. The analyst role holds the first
only — analysts read and analyse; they do not record a case's debt position or
accept a gap on the investigation's behalf.

**Privacy.** Debt items carry field names, rule names, ids, counts and numbers,
never values. Entity references are the hashed refs, so a masked entity is still
a distinct clickable thing and discloses nothing. The one place a payload is
read at all is the conflict metrics an analyzer already computed, and only the
metric names the policy lists are read — a field the policy does not name is
never opened. A test asserts no identifier from the synthetic data appears
anywhere in a partial reader's response, and another asserts audit payloads
carry the same restraint.

**API.** All authenticated, case-scoped, context-enforced and fail-closed:

- `GET /cases/{case_id}/evidence-debt`
- `GET /cases/{case_id}/evidence-debt/breakdown`
- `GET /cases/{case_id}/evidence-debt/items` (optional `category`, `status`)
- `GET /cases/{case_id}/evidence-debt/items/{debt_id}`
- `POST /cases/{case_id}/evidence-debt/recalculate`
- `POST /cases/{case_id}/evidence-debt/items/{debt_id}/acknowledge`

The last is one endpoint beyond the five the phase brief enumerates, and it is
there because the lifecycle needs it: an `ACKNOWLEDGED` state no client can reach
would be a state that only pretends to work, and recalculation is required not to
undo it. Unknown and unauthorized debt ids answer identically, so neither can be
enumerated.

**Recommendation boundary, not recommendations.** Each item records what a later
Navigator will need — `actionable`, `priority`, `blocking_reason`
(`AWAITING_HUMAN_REVIEW`, `AWAITING_ADDITIONAL_EVIDENCE`, `AWAITING_REANALYSIS`,
`AWAITING_ENTITY_RESOLUTION`), `required_capability`, and the related evidence,
resolution and finding ids. Nothing in this phase recommends an action, ranks
work for a person, or acts. It is an integration boundary and no more.

**Audit.** Through the existing EventStore, with the acting user, case and the
correlation id from the authorization decision:
`EVIDENCE_DEBT_CALCULATION_STARTED`, `_COMPLETED`, `_FAILED`,
`EVIDENCE_DEBT_CREATED`, `EVIDENCE_DEBT_RESOLVED`, `EVIDENCE_DEBT_REVISED`, plus
`EVIDENCE_DEBT_ACCESS_DENIED` — the last added for the same reason the Phase 2
denial events were, so a refused read leaves a record rather than nothing.

**Synthetic data.** CASE-004, a separate case so the Phase 5, 6 and 7A
expectations are untouched. It contains, deliberately: two register entries
scoring alike on one household number (human review); register pairs sharing
only a surname and a city (unresolved); entries agreeing on everything but an
identity reference (conflict); one handset the operator recorded under two
subscriber identities (conflict, from the analyzer's own count); an export the
operator declared `INFERRED` and that findings rest on (weak); no device
registry and one export never analysed (missing); a corrected export whose
earlier result nobody recomputed (stale); `CDR-EXPORT-DEBT-CLEAN`, which is
simply fine and whose findings carry no debt at all; and
`REG-EXPORT-DEBT-RESTRICTED` at L3. Nothing in the data describes conduct.

Two adapters gained a small symmetric capability to support this: the CDR source
now honours a per-export `classification` (an operator that reconstructed records
from partial logs is not observing them, and an adapter must never upgrade what a
source declared), and the register source a per-register `security_level`, as the
CDR source already had.

**The mandatory security test.** The restricted register's single entry is the
*only* reason one identity conflict in CASE-004 exists. The cleared reader sees
that conflict; the uncleared reader finds no trace of it — not in the total, not
in the item count, not in any category's count, not as an id, not in an
explanation, and not in a trend, and asking for the item by its id answers
exactly as an unknown id does. There is no "1 hidden conflict" counter anywhere,
because the item was never computed. A separate test asserts a narrow reader's
recalculation cannot close a gap that exists only in a wider scope, and another
sweeps every debt response for every restricted value in the fixture. The cleared
half is what makes the absence meaningful.

**Tests.** 708 passing, 197 new — 173 evidence-debt tests plus 24 that the
route-enumerating security regression suite generated automatically for the six
new endpoints. By module: 36 detector tests over views built by hand so every
answer is known in advance, 29 policy tests including deliberately broken
documents, 19 repository tests for versioning and scope keying, 57 service tests
over the real pipeline, 25 API tests, and 7 Neo4j integration tests. All 29
integration tests pass against a real Neo4j 5 Community container, and the suite
skips them and stays green with no server reachable.

The live run earned its keep on the first attempt, in the way integration tests
usually do. The live suites write under a case id unique to the run so they can
clean up exactly what they wrote, but the debt fixture asked the CDR source for
its corrected export using *that* id — and the shipped dataset is keyed to
`CASE-004`, so the fetch returned nothing. No second version was ingested, the
evidence lifecycle had nothing to supersede, and the `STALE` category was
silently absent from a live calculation. Every in-memory suite passed throughout,
because they run under `CASE-004` itself, where the two ids coincide and the
mistake cannot show.

Nothing was wrong in production code: the evidence lifecycle transitioned the
earlier result `CURRENT` -> `STALE` the moment it was handed a genuine second
version, both before and after the fix. `supersede_extra_export` now fetches
under the dataset's case id and ingests under the caller's — the split
`ReplaySource` exists for — and asserts its own postconditions, so a recurrence
fails as "the correction was not ingested as a new version" at the line that
built it rather than as a missing debt category three layers away.

**Zero external spend.** Deterministic Python and the standard library. No LLM
call, no paid service, no new runtime dependency, no queue and no scheduler.

**Phase 7B limitations.**

- **Debt is recomputed per request.** Nothing is cached; each call rebuilds the
  authorized view and re-runs every detector. Correct and simple at case scale,
  and the place to look first if a case ever gets large. A production version
  would recalculate on the events that change the inputs.
- **A record belongs to a scope, and a scope changes when evidence does.** Adding
  evidence to a case gives a reader a new scope fingerprint, so their next
  calculation starts a fresh record; earlier records are retained and readable,
  but an acknowledgement does not carry across. Carrying one across scopes would
  mean copying an investigator's free-text reason into a context it was not
  written for.
- **Dependencies are only the ones already recorded.** Staleness follows the
  evidence lifecycle's own direct transition, and finding support follows a
  signal's own `supporting_evidence_ids`. There is no dependency graph, so a
  result derived from *other* evidence is still not invalidated transitively.
- **Finding-support debt is derived, and scales with findings.** A case with many
  recorded signals resting on the same gap gets one item per signal per
  dependency category. Each names its dependency and its affected evidence, but
  the category will dominate a case that has run analytics repeatedly.
- **Conflict detection reuses two sources only** — a resolution's recorded
  conflicts and a metric an analyzer already reports. There is no independent
  cross-evidence attribute comparison, and adding one would be a second matching
  engine rather than a debt engine.
- **Only `PERSON` identity gaps reach the unresolved and human-review
  categories,** because entity resolution resolves only person observations.
- **No debt assignment, priority queue or SLA.** `priority` is a deterministic
  rank by contribution, not a workload allocation, and nothing notifies anyone.
- **No cross-case debt.** Every calculation is scoped to one case by
  construction.

## In progress

Nothing. Phase 7B is complete and committed.

## Explicitly NOT implemented

These are named because the graph, entity resolution and analytics exist now, and it would be easy to assume more of them than is true:

- **Advanced graph analytics are NOT implemented.** Phase 7A added degree, connected components, articulation-point bridges, fixed-window temporal concentration and bounded shortest paths. There is no community detection, no link prediction, no centrality beyond the bridge heuristic, and no machine learning of any kind.
- **IMEI/IMSI analytics are NOT implemented.** The `INSERTED_IN` edges record which SIM was seen in which handset, but nothing analyses SIM-swapping or hardware hopping.
- **Tower / spatio-temporal analytics are NOT implemented.** `cell_id` is carried as a property; there is no CellTower node, no geofencing and no tower-dump intersection.
- **The Evidence Navigator is NOT implemented.** Phase 7B records what a Navigator would consume — each debt item's actionability, priority, blocking reason and required capability — and stops there. Nothing recommends an action, ranks work for a person, or acts.
- **Next-best-action recommendation is NOT implemented,** and neither is non-linear workspace navigation.
- **Entity resolution beyond pairs is NOT implemented.** Resolution decides whether two person observations denote one entity, and only that: there is no transitive clustering, no canonical/golden record, and no entity type other than PERSON.
- **Frontend graph visualization is NOT implemented.** The DTOs are shaped for a future Cytoscape client; no UI exists.
- **Blockchain / integrity anchoring is NOT implemented.** Per-version SHA-256 exists as integrity metadata only; no chaining, signing or anchoring, and no admissibility claim.

## Next — exactly one subsystem

Three packages now sit beside `app/core/graph/` rather than inside it, and for
the same reason each time: entity resolution is a processing step over evidence
that *projects into* the graph, analytics is a read-model computed *from* it, and
evidence debt is a read-model computed from all three planes at once. Folding any
of them into the graph package would have blurred the boundary each phase exists
to keep sharp.

`app/core/debt/` is the newest, and it depends on the others in one direction
only: it reads their persisted state and writes nothing back to them. Nothing in
evidence, resolution or analytics imports it.

Pick exactly one of the subsystems in **Explicitly NOT implemented** above and
finish it before starting another. None of them has been started — the Evidence
Navigator, IMEI/IMSI analytics, tower and spatio-temporal analytics, the
frontend, and blockchain / integrity anchoring are all absent, and no partial
scaffolding for any of them exists in the tree.

Do not start two of them in parallel.

## Known limitations

- **Synthetic/local identities only.** Accounts are local rows created by the dev seeder; there is no user administration, password change, lockout or rotation.
- **No government identity integration and no production SSO.** `LocalIdentityProvider` is one adapter behind `IdentityProvider`; an enterprise or government provider replaces it without changes above that boundary.
- **No distributed session store.** Sessions are SQLite rows behind `SessionStore`; there is no shared session service, and no logout/revocation route (the store supports expiry marking only).
- **No production PKI**, no signing, no key management.
- **No external policy authority.** Policy is a local JSON file; there is no policy distribution, versioning or attestation.
- **Grants and the agency directory are in-memory** and reset on restart. Persisted implementations drop in behind `AccessGrantRepository` / `AgencyDirectory`.
- **Context switching picks the user's first role.** Multi-role users cannot yet choose which role a context operates under.
- **The audit log is append-only by application convention, not cryptographically.** The SQLite file is writable by anything with filesystem access; no hash chaining or tamper-evidence yet. Integrity metadata (per-version SHA-256) exists for a future `IntegrityProvider`; no admissibility claim is made.
- **Two synthetic source adapters only** (`SyntheticCDRSource`, `SyntheticSubscriberRegisterSource`), over small local datasets. No government or operator source integrations, and no FIR, financial or ANPR adapters.
- **One analyzer**, a structural CDR summary. No real telecom analytics. (Entity resolution and graph analytics are separate subsystems, not analyzers — see Phases 6 and 7A.)
- **No production object storage.** Payloads are local files; there is no replication, retention policy, encryption at rest, or lifecycle management.
- **Staleness is direct-only.** A new evidence version marks that evidence's own results STALE. There is no dependency graph, so a result derived from *other* evidence is not invalidated transitively — `mark_result_state` is the extension point. Evidence debt reports staleness where it is recorded; it does not chase it further.
- **Evidence debt is recomputed per request and never cached,** and a debt record belongs to the authorized evidence scope it was computed in.
- **No COMPARE operation and no REQUEST ACCESS workflow yet**; versions and results are retained so both can be built on top.
- **Analysis runs synchronously** inside the request. The asyncio DAG `TaskExecutor` is still an unimplemented contract.
- **Graph ingestion has no HTTP trigger.** `GraphService.ingest_case_evidence` is called in-process; there is no endpoint or scheduled job that projects evidence into the graph yet. (Entity resolution does have one: `POST /cases/{id}/entity-resolution/run`.)
- **The graph is not incrementally maintained.** Ingestion re-projects a case's current evidence; deleting or superseding evidence does not retract observations already written.
- **One graph mapper** (CDR). Subscriber-register evidence resolves but does not project into the graph; `GraphService` counts unmapped sources as skipped rather than guessing a projection. FIR, financial and ANPR sources have no mapping.
- **No frontend.**
- **No lint/type tooling** (ruff/mypy) is configured in the repo; validation is the test suite plus import checks.
- **One third-party deprecation warning remains** and is outside this codebase: Starlette's `TestClient` reports that using it with `httpx` is deprecated. It affects tests only.

## Architecture notes carried forward

- README describes the full product vision, not current state; it was intentionally left alone.
- `app/core/security.py` (SHA-256 helpers, from the original repo) is unrelated to the `app/security/` package; it remains the natural implementation for `IntegrityProvider`.
- `docker-compose.yml` omits a frontend service because no frontend code exists yet.
