# SHADOW-INTEL — local development

Everything runs locally. No paid service, no cloud account, no managed database.

## First run

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
```

The suite passes with no Neo4j running — the integration tests skip themselves.
That is the fastest way to confirm the checkout is sound.

## Configuration

Settings live in `backend/app/core/config.py` and are read from the environment
or from `backend/.env`. `backend/.env.example` documents every one of them and
already carries the defaults, so copying it and changing nothing is a no-op:

```bash
cp .env.example .env
```

Two things to know:

- **Unknown keys are rejected.** A `.env` containing a key that is not a setting
  stops startup. That catches a typo in `NEO4J_PASSWORD` rather than silently
  falling back to a default, and a test asserts `.env.example` still loads.
- **`DEV_SEED_PASSWORD` is not a `.env` key.** The seeder reads it from the
  process environment only, so a password for the synthetic accounts never has
  to sit in a file.

`SECRET_KEY` may be left blank outside production: an ephemeral key is generated
per process. With `ENVIRONMENT=production` a blank key fails startup, on purpose.

## Neo4j

```bash
docker compose up -d neo4j     # start; bolt on 7687, browser on http://localhost:7474
docker compose ps              # the service reports its own health
docker compose stop neo4j      # stop, keeping data
docker compose down            # stop and remove containers, keeping data
docker compose down -v         # ALSO deletes the graph volumes
```

Data lives in the named volumes `shadow_intel_neo4j_data` and
`shadow_intel_neo4j_logs`, so it survives `down` and a container rebuild. Only
`down -v` discards it.

Default credentials are `neo4j` / `shadowintel`, a development value set in both
`docker-compose.yml` and `.env.example`. Change them together — the healthcheck
authenticates with the same pair.

## Synthetic development accounts

```bash
DEV_SEED_PASSWORD='choose-a-local-password' python -m app.security.identity.seed
```

Creates USR-001 `dev.investigator` (L2, POLICE), USR-002 `dev.analyst`
(L1, FINANCIAL_CRIME) and USR-003 `dev.disabled`. The seeder refuses to run
without a password, so no credential is ever committed.

Grants are in-memory and reset on restart, so a freshly started process has the
agency grants from seeding but no case grants.

## Running the backend

```bash
uvicorn app.main:app --reload          # from backend/
curl localhost:8000/health             # {"status":"ok"}
curl localhost:8000/ready              # {"status":"ready","environment":"development"}
```

Interactive API docs: <http://localhost:8000/docs>.

Neither health endpoint probes Neo4j. The application is built to serve every
non-graph route with the graph down, so a readiness check that failed on an
unreachable Neo4j would call a working process unhealthy. Graph availability
surfaces where it matters — the graph routes answer `GRAPH_UNAVAILABLE` (503),
and `docker compose ps` carries Neo4j's own healthcheck.

## Tests

```bash
python -m pytest                        # everything; integration skips if Neo4j is down
python -m pytest -m "not integration"   # no external service, always runnable
python -m pytest -m integration         # only the live Neo4j suites
python -m pytest -q --durations=10      # find the slow ones
```

The suites, by kind:

| kind | files | needs |
|---|---|---|
| unit | `test_resolution_matching`, `test_clearance_policy`, `test_authorization`, `test_graph_mapping`, `test_core_interfaces`, `test_plugin_registry`, `test_config_secrets` | nothing |
| service | `test_evidence_lifecycle`, `test_graph_service`, `test_resolution_service`, `test_authentication`, `test_event_store`, `test_security_audit`, `test_resolution_repository`, `test_neo4j_repository` | nothing |
| API | `test_auth_api`, `test_evidence_api`, `test_graph_api`, `test_resolution_api`, `test_security_regression`, `test_health`, `test_smoke` | nothing |
| integration | `test_neo4j_integration`, `test_resolution_neo4j_integration`, `test_end_to_end_integration` | a reachable Neo4j |

API suites compose the real stack through `tests/api_harness.py`; only the graph
backend is a fake. `test_end_to_end_integration` puts the real Neo4j behind that
same stack and walks ingest → graph → resolution → review over HTTP.

Integration suites use `tests/neo4j_support.py`, which writes under a case id
unique to each test and deletes exactly the nodes that test wrote, so a run
leaves the database as it found it — verified by comparing node counts across a
full integration run.

Every store is created under pytest's `tmp_path`, so a run never touches
`backend/data/` and two runs cannot see each other's state.

## Troubleshooting

**`20 skipped` and you expected them to run.** Neo4j is not reachable. Check
`docker compose ps`, then `docker compose up -d neo4j` and wait for `(healthy)`
— the first start takes ~30s.

**`ValidationError: Extra inputs are not permitted`.** Your `.env` has a key
that is not a setting. Compare it against `.env.example`; remove the extra key
or add the setting.

**`security policy not found at ...`.** `CLEARANCE_POLICY_PATH` is wrong.
Relative paths resolve against `backend/`, so the value is
`app/security/policy/clearance_policy.json`.

**`GRAPH_UNAVAILABLE` (503) from a graph route.** Only graph routes depend on
Neo4j. Confirm it is up, and that `NEO4J_URI` matches where it is listening —
`bolt://localhost:7687` from the host, `bolt://neo4j:7687` from inside compose.

**`AUTHENTICATION_FAILED` on every login.** The identity database has not been
seeded, or was seeded with a different `DEV_SEED_PASSWORD`. Re-run the seeder.
Every login failure returns the same response by design; the real reason is in
the event store as `LOGIN_FAILED`.

**`NO_ACTIVE_CONTEXT` (403).** Authenticating is not selecting an agency. Call
`POST /context/switch` with an agency the user actually holds.

**Old `CASE-IT-*` nodes in the graph browser.** Integration runs before this
version leaked orphan `Evidence` nodes. Clear them with:

```cypher
MATCH (n:Evidence) WHERE NOT (n)--() AND n.case_id STARTS WITH 'CASE-IT-' DELETE n
```

## What is deliberately not here

No task runner, no Makefile and no wrapper scripts: every workflow above is a
single command, and a script would only add a layer to keep in sync. No lint or
type-check tooling is configured yet — validation is the test suite.
