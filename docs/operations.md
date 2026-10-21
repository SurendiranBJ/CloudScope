# CloudScope Operations

## Current operating model

The backend runs startup and scheduled scans through the scan coordinator using the AWS credentials configured on the backend. A Redis-backed owner-token lease prevents overlapping coordinated scans when Redis is reachable. The heartbeat renews the lease periodically and the worker releases it on completion. The scan lock serializes scans globally.

Production mode requires Redis and fails scan locking closed when Redis is unavailable. Local non-production mode may use process-local fallback behavior, which is not suitable for multi-worker coordination.

## Durable state

Relational storage contains scan runs, published snapshots, finding state/history, audit events, and simulation drafts. Legacy project records/columns may remain in existing databases for compatibility but are not used to select scan credentials. Redis provides cache and coordination, not the sole durable record. Current schema setup uses create-all and ad hoc migrations; use backups and do not assume automatic schema upgrades are production-safe. A versioned migration workflow remains open.

## Health and support endpoints

- /live is a liveness probe.
- /ready checks core database, Redis, and Neo4j dependencies.
- /health provides application metadata.
- /health/aws performs an AWS identity/connectivity check and is admin-protected.
- /health/dependencies and /operations expose service/scan diagnostics according to route authorization.
- /metrics exposes Prometheus metrics; restrict network access at the deployment layer until a dedicated access policy is in place.

Confirm route-level behavior against the deployed version before exposing diagnostic endpoints publicly.

## Routine operations

1. Check service health and the latest scan result.
2. Confirm scan status reaches a terminal success/partial/failure result and a snapshot ID is published.
3. Review failed regions/collectors before treating missing resources as absent.
4. Confirm the backend-configured AWS account identity before investigations or exports.
5. Inspect audit events for scan, finding, simulation, and administrative changes.
6. Keep database and Neo4j backups protected and test restoration.
7. Alert on stale scans, lock contention, persistence failures, degraded dependencies, and high error rates.

Operations dashboard presence does not itself provide alert delivery, backup validation, or incident response.
