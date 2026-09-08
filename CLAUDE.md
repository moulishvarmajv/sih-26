# SHADOW-INTEL — Engineering Brief

Agency-agnostic evidence intelligence & investigation orchestration platform (SIH26189, MHA). One core; agencies (Police, Cyber Crime, Financial Crime, ...) are plugins.

## Architecture boundaries (do not blur these)

- **Governance/Security** — identity, roles, clearance, authorization, privacy. Governs everything else.
- **Knowledge plane** — Neo4j knowledge graph: what the investigation knows.
- **Execution plane** — asyncio Task/DAG executor: what the system needs to compute. NetworkX assists graph algorithms; it is not the executor.
- **Investigator workspace** — non-linear navigation (FIR → Person → Phone → CDR → ... → back to FIR). Not the same thing as the execution graph.

`InvestigationState`, `ExecutionState`, `EvidenceState`, and `AuthorizationState` are distinct concepts — do not conflate them.

## Non-negotiable rules

1. **Plugin-first.** No agency-specific `if/else` branching in core code. New agencies register through `PluginRegistry` and implement the `AgencyPlugin` contract (`backend/app/plugins/`).
2. **Security-first, fail closed.** Clearance ≠ authorization. Every evidence access, agency switch, and case access is checked server-side via `SecurityService` (`backend/app/security/service.py`). The frontend is never the source of truth for authorization. An `AgencyContext` is a *claim*, not a grant — re-evaluate it every time, and never let it claim more clearance than the user holds.
   - **Clearance levels are policy data.** Never compare level codes (`"L2" > "L1"`) in business logic — ask `ClearancePolicy`. Level names, ordering and the fail-closed default live in `app/security/policy/clearance_policy.json`.
   - **Keep the layers apart:** repositories resolve *facts*, the engine turns facts into a decision (pure, no I/O, no clock), the service sequences the two and audits the outcome, routes only call the service.
   - **Every authorization outcome is audited** — allow, partial and deny. Decisions and audit payloads carry decision facts and field *names* only, never resource content.
   - **Authentication ≠ authorization.** `IdentityProvider` answers "who is this?"; the engine answers "may they?". Identity comes only from the session boundary (`get_current_user`) — never from a client-supplied id, header or body field.
   - **Password material stops at the identity boundary.** `UserAccount` carries the hash and stays inside `security/identity/`; everything above it uses the domain `User`, which has no password field.
3. **Evidence is reusable state; viewing must not trigger processing.** VIEW / ANALYZE / REANALYZE / COMPARE are distinct operations. VIEW only reads. ANALYZE returns the CURRENT result if there is one and computes only when there isn't. REANALYZE is the only operation that deliberately creates work. Reprocessing creates a new `ProcessingRun` and result — it never overwrites history; superseded and stale results stay readable.
   - **Authorize before disclosing.** Read the AuthorizationDecision first, and only then fetch a payload — never load protected content and filter it afterwards.
   - **Apply masking server-side.** A PARTIAL decision names fields; `security/privacy/masking.py` applies them. Never send a raw value to a client expecting the client to hide it, and never mask by hand in a route.
4. **Trust classification is permanent.** `OBSERVED` / `DERIVED` / `INFERRED` / `GENERATED` — never silently upgrade a lower tier to a higher one. Findings retain provenance. Evidence carries a second, independent axis — `security_level` (a clearance code) drives access; `classification` drives trust. Never merge them.
5. **Zero mandatory external spend.** No OpenAI/Anthropic/Gemini APIs, no paid cloud services, no Redis/Celery/Kafka/Kubernetes, no managed Neo4j, no paid blockchain RPC. Local/open-source only.
6. **Flight recorder is event-driven.** Investigation history is an append-only local event log, not derived state.

## Coding standards

- Python 3.11+, typed (dataclasses/Protocols for contracts; no untyped `Any` leakage across module boundaries).
- Interfaces are small and testable (`typing.Protocol`) before they get real implementations. Don't write methods that pretend to work.
- Prefer existing dependencies (see `backend/requirements.txt`) over adding new ones.
- No comments explaining *what* code does; only *why*, when non-obvious.

## Process rules

- **Inspect before modifying.** Read the actual current file/module before changing or extending it. Don't assume the architecture doc matches the code.
- **Don't build future infrastructure prematurely.** Establish the module boundary and typed contract for a concern before it's needed elsewhere; don't implement the business logic behind it until a task actually requires it.
- **Testing is required** for anything with real logic (registries, executors, engines). Contracts/Protocols need only an import-and-shape test. Don't add placeholder tests that assert nothing.

## Key paths

- `backend/app/core/` — domain models, evidence, execution, graph, investigation, navigator, audit contracts.
- `backend/app/security/` — identity, roles, clearance, policy, authorization, privacy.
- `backend/app/plugins/` — `AgencyPlugin` contract + `PluginRegistry` + one subpackage per agency.
- `backend/app/infrastructure/` — logging, integrity/hashing, and other cross-cutting adapters.
- `docs/IMPLEMENTATION_STATE.md` — current build status; update it as phases land.
