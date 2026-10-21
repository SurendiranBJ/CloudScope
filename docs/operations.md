# CloudScope Operations

**Updated:** 2026-10-22
Operational endpoints and role restrictions can evolve; confirm OpenAPI for the deployed version before automating them.

## Account and scan lifecycle

The backend uses its configured AWS profile/default credential chain. That identity selects the single AWS account analyzed by the deployment. Confirm the account from the backend environment before scans or exports. The UI does not choose a project or assume a user-selected cross-account role.

The scheduler requests an initial scan at startup. A manual or region-change scan can also be requested. Scan coordination attempts a Redis lease with owner token and heartbeat; non-production fallback may use process-local coordination. Production fails scan locking closed when Redis is unavailable.

Scheduled scans use fixed delay: the job waits for a started scan to reach terminal status, then queues the next scan after the configured `SCAN_INTERVAL_MINUTES`. A scan duration therefore adds to the idle interval. It should not overlap its own next scheduled scan.

## Scan status and publication

The scan has an ID, status, phase/collector progress, timestamps, and region outcomes. Sixteen collector groups report `PENDING`, `RUNNING`, `SUCCESS_WITH_DATA`, `SUCCESS_EMPTY`, or `FAILED` states (some services are combined into `ExtendedAWS`). A successful empty result differs from a failed collector. Critical collector failure prevents an empty/incomplete dataset from replacing the last known-good published snapshot.

Review all of the following before concluding a resource or permission is absent:

1. Overall scan status (`SUCCESS`, `PARTIAL`, `FAILED`, or active state).
2. Snapshot ID and publication time.
3. Resolved/attempted, successful and failed AWS regions.
4. Per-collector and regional status, including permission errors and timeouts.
5. Relevant AWS service permissions, region enablement and API throttling.

Published snapshots are immutable read models; request-level snapshot pinning keeps related API reads on the same version. Up to ten snapshots are retained by default. The historical UI is read-only; exit it to return to current live state.

## Durable and transient state

- **SQL:** scan runs and snapshots, finding state/history, audit events and simulation drafts. Back it up and protect exports. Current schema setup is table creation plus compatibility column alterations, not versioned migrations.
- **Redis:** cache and coordination. In-memory fallback is for local/non-production use, not multi-worker production.
- **Neo4j:** graph data. Verify connectivity and backup separately.
- **Local scanner files:** do not assume these are the authoritative durable snapshot source; inspect the persisted snapshot and scan run.

Legacy project tables/columns may remain in existing databases. They do not activate Projects UI or account registration. Current account selection comes from backend credentials.

## Health and diagnostic endpoints

In the default FastAPI mount, health routes are available at the root and under `/api/v1`:

- `GET /live`: process liveness only; no dependency or AWS probe.
- `GET /ready`: checks database, Redis and Neo4j. It does not require AWS to be available.
- `GET /health`: version/runtime/region information; admin protected.
- `GET /health/aws`: STS credential/identity diagnostic; admin protected.
- `GET /health/dependencies`: detailed dependencies plus AWS diagnostic; admin protected.
- `GET /metrics`: Prometheus exposition. Current production implementation denies access without a configured metrics token; the Settings class does not currently expose such a token, so production metrics may remain unavailable unless code/config is extended.
- `GET /api/v1/operations/overview`: admin-only operations summary.

Health route availability differs from authorized diagnostic access. Keep service ports and metrics behind reviewed network controls.

## Routine operational checks

1. Check liveness/readiness, authenticated service access and dependency state.
2. Verify the STS account identity in the same backend runtime that scans.
3. Confirm a scan reaches terminal status and publishes a snapshot ID.
4. Review region failures, service collector failures and `SUCCESS_EMPTY` states before interpreting inventory.
5. Compare scan time, duration and scheduled next run; sustained run time may make the configured idle interval misleading to users.
6. Verify snapshot retention and test SQL/Neo4j backup restoration.
7. Review audit events and finding lifecycle changes.
8. Alert externally on stale scans, failed/partial regions, lock loss, persistence errors, API error rates and dependency degradation.

The app contains diagnostic and summary screens; it does not by itself deliver on-call alerts, validate backups or perform incident response.
