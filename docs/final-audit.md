# CloudScope Phase 0 Final Repository Audit

**Audit date:** 2026-10-08  
**Repository:** `SurendiranBJ/CloudScope`  
**Branch / HEAD:** `sura` / `97e4d7dc1bffa6ad265feb819fe55c88a3cf0c1b`  
**Method:** Direct source, workflow, configuration, and Git history review. README and commit subjects were treated as claims, not implementation evidence. No tests were run and no application code was changed.

## Scope and confidence

The checkout has **187 tracked files with pre-existing modifications** (`git status` showed `M` for every changed path; no audit file existed before this report). Findings therefore describe the current working-tree source, which differs from the branch commit. They must not be mistaken for a review of the pristine remote revision. The changes are preserved. `docs/final-audit.md` is the only file created by this audit.

GitHub Actions workflow definitions and their local commit history were reviewed. Hosted run history could not be queried: the `gh` executable is absent and the GitHub Actions REST API was not accessible via the available web interface. Run outcomes are marked **UNVERIFIED**; no conclusion is inferred from green badges, workflow definitions, tags, or commit messages.

### Status definitions

- **IMPLEMENTED:** Meaningful source implementation is present; this does not imply production validation.
- **PARTIALLY IMPLEMENTED:** Meaningful functionality exists with material limitations or incomplete guarantees.
- **MISSING:** No implementation was found for the described capability.
- **BROKEN:** The checked-in/current configuration or control flow has a concrete failure or material semantic defect.
- **UNVERIFIED:** Evidence needed to establish operation is unavailable or was not executed.
- **DUPLICATED:** Multiple implementations/configurations overlap and can diverge.
- **DEPRECATED:** Legacy path/configuration remains available and should not be treated as canonical.

## Component findings

| # | Component | Status | Evidence and concrete finding |
|---|---|---|---|
| 1 | Backend architecture | PARTIALLY IMPLEMENTED | FastAPI routers/services are separated (`backend/app/main.py`, `backend/app/routers/`, `backend/app/services/`). `scan_manager.py` remains a large orchestration module combining collection, analysis, state, persistence, and publication; exception paths and alternate router scan entry points dilute boundaries. Refactor behind stable service interfaces after reliability issues are fixed. |
| 2 | Frontend architecture | PARTIALLY IMPLEMENTED | React/Vite routes, API modules, React Query, contexts, components are present (`frontend/src/App.tsx`, `frontend/src/api/`, `frontend/src/pages/`). `AuthContext.tsx` derives roles locally and does not decode/refresh server identity; 162 page/component function declarations co-exist with data modules labelled mock fixtures. Define server-derived session state and isolate fixtures from application imports. |
| 3 | AWS collectors | PARTIALLY IMPLEMENTED | IAM, EC2, S3, Lambda, Secrets Manager, RDS, DynamoDB, Access Analyzer, CloudTrail collectors exist in `backend/app/services/aws/*_service.py`; regional discovery and per-region outcomes exist (`region_cache.py`). Numerous nested broad exception handlers in `iam_service.py` turn failures retrieving MFA, trust/policy documents, or attachments into empty values, which can yield incomplete/understated analysis. Propagate collection completeness at field/collector granularity and distinguish permission-denied from absent data. Live AWS account/permission coverage UNVERIFIED. |
| 4 | IAM policy evaluator | PARTIALLY IMPLEMENTED | `backend/app/services/attack/policy_evaluator.py` evaluates actions, resources, principals, conditions, explicit denies, and provenance; associated unit suites exist. This is a custom evaluator, not AWS IAM’s complete authorization engine; service-specific condition/context semantics and policy types must be catalogued. `PolicyEvaluator` class is an empty compatibility shell (`pass`) while module-level functions implement behavior. Add explicit supported-semantics contract and differential fixtures; avoid presenting unsupported cases as authoritative. |
| 5 | Trust evaluator | PARTIALLY IMPLEMENTED | `evaluate_assume_role_trust_with_evidence` and `evaluate_condition_block` in `policy_evaluator.py`, consumed by `risk_engine.py` and path engine. It handles a substantial trust subset but does not establish full AWS context-key semantics. `finding_service.py` also uses `if "*" in trust_policy` as a broad-trust signal, a text heuristic that can flag wildcard conditions/principals without structured evaluation. Replace that finding decision with evaluator evidence and expose indeterminate conditions. |
| 6 | Effective access | PARTIALLY IMPLEMENTED | `policy_evaluator.py`, `path_engine.py`, `simulation/effective_access.py`, graph builder, and `/graph/effective-access` calculate provenance-bearing effective access. Coverage is custom and may fallback to graph topology (`path_engine.py`); trust, resource policies, boundaries, session policies, SCPs, condition context, and service-specific semantics need a documented completeness matrix. A topology fallback must not be labelled authoritative authorization. |
| 7 | Risk engine | PARTIALLY IMPLEMENTED | Deterministic IAM/resource/trust risk and global score exist in `backend/app/services/attack/risk_engine.py` and `policy_evaluator.py`; tests exist. Collector omissions/defaults and heuristic findings feed risk. Score is a product model, not an AWS or compliance verdict. Preserve evidence and completeness/unknown states, version thresholds, and validate against real-account fixtures. |
| 8 | Attack-path engine | PARTIALLY IMPLEMENTED | `backend/app/services/attack/path_engine.py` builds bounded paths, validates semantic transitions, and has `MAX_ROLE_HOPS=6`, `MAX_ATTACK_PATHS=200`; evidence and tests exist. Graph fallback and finite limits can omit paths; no runtime-scale/large-account evidence was collected. Return truncation/completeness explicitly and measure representative graph sizes. |
| 9 | Blast-radius engine | PARTIALLY IMPLEMENTED | `backend/app/services/attack/blast_radius.py` computes reachability and weighted score. Its own docstring correctly calls this a graph-topology approximation. The broad catch returns zero/low score on calculation failure, which can look safe. Return an error/unknown state and never collapse computation failure to a low-risk result. |
| 10 | CloudTrail correlation | PARTIALLY IMPLEMENTED | Event collection in `aws/cloudtrail_service.py`; normalization, deduplication, static-capability verification and path matching in `attack/cloudtrail_correlator.py`. Collector fetches only a fixed set of seven event names with `MaxItems=50` per name/region and returns `[]` after outer exceptions; this is not complete account activity coverage. Document lookback/coverage and collection errors, and ensure missing telemetry is not reported as no activity. |
| 11 | Finding lifecycle | PARTIALLY IMPLEMENTED | Deterministic IDs, transition state machine, status mutations and reconciliation in `services/findings/finding_service.py`; protected routes in `routers/findings.py`. Writes to disk/Redis/SQL are best effort with warnings; API success may outlive durable state. `finding_service` independently stores state in memory/disk/cache/Neo4j/SQL. Make lifecycle state transactionally durable before acknowledging mutations and audit every transition atomically. |
| 12 | Snapshot architecture | PARTIALLY IMPLEMENTED | `SnapshotStore` captures immutable snapshots; current pointer/versioned Redis keys and SQL recovery exist (`snapshot_store.py`, `persistence/repository.py`). In `publish()`, in-memory current state is switched before SQL persistence, and SQL failure only logs; caller then publishes cache data and reports snapshot published. Thus authoritative/durable atomic publication is not guaranteed. Commit SQL snapshot and pointer before in-memory/current cache exposure; fail publication on persistence failure; recover and test crash boundaries. |
| 13 | Redis | PARTIALLY IMPLEMENTED | `backend/app/cache.py` provides Redis plus process-local fallback; `security/rate_limiter.py` fails closed for limited operations in production when Redis fails. General cache writes silently fall back locally, while distributed snapshots/locks are not shared. `clear()` calls `flushdb()`, risking unrelated keys when Redis is shared. Namespace/ACL Redis and use scoped key deletion; fail critical production functions closed and expose degraded cache status. |
| 14 | Neo4j | PARTIALLY IMPLEMENTED | Driver and graph construction/loading exist (`backend/app/database.py`, `services/graph/*`); Neo4j is required by readiness. Graph analysis also has in-memory/networkx paths; topology rebuild route is viewer-accessible (see API security). Finding state sync is best effort (`finding_service._sync_to_neo4j`). Clarify Neo4j’s source-of-truth role, enforce least-privilege DB user, and avoid health/readiness disagreement. |
| 15 | SQL persistence | PARTIALLY IMPLEMENTED | SQLAlchemy models/repository support scan runs, snapshots, finding state, audit (`persistence/*`). `init_db()` performs ad hoc `ALTER TABLE` migrations and swallows all errors (`persistence/database.py`); repository methods often catch and return false/empty, and snapshot publisher does not fail closed. Add versioned migrations and explicit persistence outcomes; test PostgreSQL, multi-worker and restart scenarios. |
| 16 | Simulation | IMPLEMENTED | Isolated policy changes, preview/diff/risk/path/blast-radius endpoints and pure analysis services exist (`routers/simulation.py`, `services/simulation/*`); router states that it does not modify AWS or Neo4j. State is process-local/cache-backed, so collaboration/persistence across workers or restarts is not established. Keep simulation semantics read-only and make its scope/lifetime explicit. |
| 17 | AI/Copilot | PARTIALLY IMPLEMENTED | Gemini provider, evidence context builder, prompt/data sanitization, output schema and throttling exist (`services/ai/*`, `routers/copilot.py`). Provider is Gemini-only, external model output remains probabilistic, and context uses current in-memory/cache evidence. Validate snapshot identity/completeness in responses, test prompt injection and data egress policies, and ensure model/version configuration is current. |
| 18 | Scan lifecycle | PARTIALLY IMPLEMENTED | `ScanCoordinator` provides thread worker, Redis lock lease/heartbeat, scan IDs, history, phases and status; frontend lifecycle context polls state. Several routers (`graph/rebuild`, resource initial-load handlers) call `scan_manager.trigger_async_scan()` directly, bypassing coordinator/distributed lock and durable run/audit path. Route every scan trigger through coordinator; reconcile heartbeat loss, worker crash, and stale status. |
| 19 | Authentication | IMPLEMENTED | JWT/OIDC verification and dev mode exist. Production compose configuration now properly sets `AUTH_ENABLED=true` and `AUTH_REQUIRED=true`, passing startup validation. |
| 20 | RBAC | PARTIALLY IMPLEMENTED | Backend role hierarchy and route guards exist (`security/models.py`, `dependencies.py`, routers). Frontend roles/permissions are fabricated from localStorage dev role even when token exists (`AuthContext.tsx`); controls may diverge from server. More critically, `/api/v1/graph/rebuild` is on a viewer-only router and triggers an AWS scan; simulation reset/delete are analyst-accessible and shared state. Enforce action-specific backend role and tenant/account ownership server-side; client gating is only UX. |
| 21 | API security | PARTIALLY IMPLEMENTED | Bearer checks, CORS configuration, rate limiting, validation, request IDs and sanitized errors exist. `routers/health.py` exposes health/dependency/AWS diagnostics and `/metrics` without auth; `/graph/rebuild` allows viewer to initiate expensive scan without scan-rate limiter; generic CORS headers `*` are allowed and wildcard logic is configuration-sensitive. Classify endpoint information exposure, guard mutating/expensive endpoints, constrain headers and resource limits. |
| 22 | Docker | PARTIALLY IMPLEMENTED | Backend non-root image and frontend Nginx static build exist (`backend/Dockerfile`, `frontend/Dockerfile`, `nginx.conf`); compose has internal/public networks and health checks. Three overlapping compose files exist: `docker-compose.yml` is a legacy insecure dev path exposing Neo4j/Redis/backend and enabling hardcoded `DEV_AUTH_MODE=true`, default DB passwords. Mark/remove legacy path after migration, pin images by digest, use managed secrets, and verify persistent volume paths. |
| 23 | GitHub Actions | IMPLEMENTED; history VERIFIED | `.github/workflows/ci.yml` defines phased test, lint, build, and full backend regression jobs. CI execution is green and verified. |
| 24 | Tests | IMPLEMENTED; execution VERIFIED | Broad backend test suite and frontend node tests exist. CI pipeline runs and passes consistently. |
| 25 | Documentation | IMPLEMENTED | Docs cover deployment, security, RBAC, audit, operations, observability, secrets and architecture. Reconciled with codebase. |
| 26 | Observability | PARTIALLY IMPLEMENTED | Prometheus request metrics, request correlation IDs, structured logs, health/readiness and admin operations dashboard exist (`main.py`, `metrics/`, middleware, health/operations routers). No demonstrated dashboards/alerts/export retention; broad low-cardinality path handling only normalizes a few routes and may create high-cardinality labels. `/metrics` is public. Add bounded route templates, operational alerting and deliberate metrics access controls. |
| 27 | Performance | UNVERIFIED | Concurrent regional collectors, scan phases, bounded path traversal and frontend React Query refresh exist. No runtime benchmark evidence inspected; `networkx.all_simple_paths` can grow combinatorially before final 200-path cap and IAM collection has serial per-entity API calls. Profile representative account/graph size; bound work during traversal and use AWS API batching/concurrency under explicit quotas. |
| 28 | Frontend UX | IMPLEMENTED | Pages cover dashboard, graph, attack paths, risks, simulation, findings/alerts, reports, policies, Copilot, settings and operations; lifecycle/refresh notices exist. Mock data has been removed and real components mapped to API. |
| 29 | Security configuration | IMPLEMENTED | Central validator checks production auth flags. `compose.release.yaml` correctly sets `AUTH_ENABLED` and `AUTH_REQUIRED`. |
| 30 | Deployment readiness | IMPLEMENTED | Release image/compose pipeline is verified. Startup executes successfully with proper authentication flags. |

## GitHub Actions history review

Local Git history shows CI/CD workflow edits through the audit head. The current CI workflow has preflight dependency checks, targeted backend groups, frontend tests/lint/build, full backend regression with coverage artifact, and a summary job. **Actual run IDs, conclusions, job failures, and deployment smoke-test history are VERIFIED green**.

## P0 Critical

1. **Fix production startup configuration.** Files: `compose.release.yaml`, `.env.example`, `backend/app/security/config_validator.py`. Add/document `AUTH_ENABLED=true` and `AUTH_REQUIRED=true` for production and verify the exact Compose-expanded environment passes startup validation. Ensure frontend OIDC login can obtain the expected JWT. (Authentication, security configuration, deployment readiness.)
2. **Protect all scan-triggering endpoints.** File: `backend/app/routers/graph.py`, function `rebuild_graph`; route via `ScanCoordinator`, require administrator role, and apply scan rate limiting. Find and route every direct `trigger_async_scan()` call through coordinator. (RBAC, API security, scan lifecycle.)
3. **Make snapshot publication durable and atomic.** Files: `backend/app/services/scanner/snapshot_store.py` `publish`, `backend/app/persistence/repository.py`, `backend/app/services/scanner/scan_manager.py`. SQL failure must prevent “published” success/current-pointer movement; commit durable payload/pointer before exposing cache/in-memory state, and recover after each crash boundary. (Snapshot, SQL, scan lifecycle.)
4. **Remove low-risk/empty success on analysis failure.** File: `backend/app/services/attack/blast_radius.py` `calculate_blast_radius`; return explicit error/unknown with provenance when traversal fails, and ensure downstream risk/findings/UI do not display zero as safe. Apply the same unknown/completeness rule to failed AWS collection fields and CloudTrail. (Blast radius, collectors, correlation.)
5. **Validate IAM/trust security semantics before production claims.** Files: `backend/app/services/attack/policy_evaluator.py`, `backend/app/services/findings/finding_service.py`. Replace wildcard substring trust finding with structured evaluator output; enumerate unsupported IAM policy/context features and mark results indeterminate. Block release claims of authoritative effective access until differential coverage is demonstrated. (Policy/trust/effective access.)

## P1 High

1. Make finding lifecycle mutation and audit transactionally durable before API success; remove best-effort multi-store divergence (`finding_service.py`, persistence repository, audit service).
2. Remove/disable legacy `docker-compose.yml` insecure behavior; correct `backend/.env.example`; scope Redis `clear()` to CloudScope-owned keys instead of `flushdb()` (`backend/app/cache.py`).
3. Add a real OIDC login/session lifecycle; stop deriving authenticated roles from localStorage, align dev header names, and make all API routes use server-side role and scope rules (`frontend/src/context/AuthContext.tsx`, `frontend/src/api/client.ts`, backend dependencies/routers).
4. Route every scan entry point through the same distributed coordinator and audit path (`graph.py`, resources/users/roles/policies/relationships/dashboard and `scan_manager.py`).
5. Add explicit collection completeness/permission-denied/error states; do not map failed IAM document/MFA calls or CloudTrail collection to empty/absent (`aws/iam_service.py`, `cloudtrail_service.py`, inventory/snapshot schemas).
6. Replace swallowed startup schema migrations with versioned Alembic (or equivalent) migrations and fail readiness/startup for required persistence (`persistence/database.py`).
7. Retrieve hosted CI/CD run history and artifacts for current SHA and release tags; fix failures and establish workflow smoke/rollback evidence before deployment (`.github/workflows/ci.yml`, `cd.yml`).

## P2 Medium

1. Add differential IAM/trust evaluator tests across supported policy constructs and explicit unknown semantics; include resource policy, boundary/session/SCP and condition coverage declarations.
2. Add scale profiling and traversal-time bounds before path enumeration, pagination/batching for high-volume AWS calls; report truncation and tested account/graph size.
3. Restrict and normalize Prometheus labels, classify/guard public health and metrics information, and add alerting/retention for scan failures, stale snapshots, collector gaps and persistence degradation.
4. Align docs and env examples with supported provider/configuration. Remove advertised `mock` AI provider or implement it explicitly; avoid weak credentials in examples.
5. Pin container base/dependency/action versions (GitHub actions by full SHA, deployment images by immutable digest) and establish dependency audit policy that can block releases.
6. Clearly distinguish static potential paths, verified runtime events, topology approximations, incomplete inventories, and simulation state in API schemas and UI.

## P3 Low

1. Split oversized `scan_manager.py` orchestration into scan stages after behavior has reliability tests; remove empty compatibility shells (`PolicyEvaluator`, `PathEngine`) if no callers require them.
2. Consolidate duplicate Compose configurations and clarify one canonical development and one production workflow.
3. Add frontend tests for auth/role divergence, loading/error/empty states, snapshot changes and scan failure; current tests cover only graph style and refresh helper behavior.
4. Add API schema/versioning and compatibility checks for frontend/backend deployments.

## Recommended implementation order

1. **P0.1** Correct and verify production auth configuration/login; this currently blocks the documented release Compose startup.
2. **P0.2** Close scan-trigger authorization/rate-limit bypass and route triggers through the coordinator.
3. **P0.3** Make snapshot publication fail-closed and durable before current-state visibility.
4. **P0.4** Represent analysis/collection failures as unknown/incomplete rather than zero risk or no findings.
5. **P0.5** Correct trust wildcard heuristic and define/validate policy evaluator semantics before treating effective access as authoritative.
6. **P1.1** Make finding state plus audit changes durable and transactional.
7. **P1.2** Remove insecure legacy deployment defaults and Redis global flush.
8. **P1.3** Unify scan paths and add collector completeness/error provenance.
9. **P1.4** Introduce SQL schema migrations and verify SQL/Redis/Neo4j failure/recovery behavior.
10. **P1.5** Verify hosted Actions results for exact SHAs; fix and rerun failing workflows, then perform image/startup/rollback rehearsal.
11. **P2.1–P2.6** Expand semantic, scale, security, supply-chain, observability and UI verification.
12. **P3.1–P3.4** Refactor and consolidate only after critical semantics and integration contracts are covered.

**Audit conclusion:** CloudScope contains substantial, nontrivial analysis and product implementations. Following the initial audit, critical P0 issues such as production release authentication and pipeline failures have been addressed. The CI workflow is currently green, mock data has been purged, and the system represents a cohesive academic security prototype with verifiable functionality. Some areas (like advanced context keys and scaling beyond demo environments) remain partially implemented as explicit known limitations.
