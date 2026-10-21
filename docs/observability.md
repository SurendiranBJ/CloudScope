# Observability and Health

CloudScope provides health checks, structured request logs, request IDs, scan status/collector progress, operations summaries and Prometheus metrics code. These are diagnostic primitives, not a complete monitoring or alert-delivery service.

## Health checks

| Endpoint | Behavior | Access/use |
| --- | --- | --- |
| `GET /live` | Memory/process liveness; does not probe AWS, Redis, Neo4j or SQL. | Container/orchestrator liveness. |
| `GET /ready` | Checks SQL, Redis and Neo4j connectivity. AWS availability is intentionally excluded. | Container readiness. |
| `GET /health` | Version/build/startup and current region-mode metadata. | Admin-protected diagnostic. |
| `GET /health/aws` | Calls STS for credential/account diagnostics; does not disclose secret keys. | Admin-protected; AWS connectivity check. |
| `GET /health/dependencies` | Detailed SQL, Redis, Neo4j and AWS status. | Admin-protected; treat as sensitive operational information. |
| `GET /api/v1/operations/overview` | Scan/lock/scheduler/storage and recent operational data. | Administrator role. |

The health router is mounted at root and included in API v1. Verify the exact route against the deployed OpenAPI schema. A ready backend can still lack valid AWS credentials or permissions and fail a scan.

## Scan and application telemetry

The scan status API/UI exposes scan ID, active phase, elapsed time, collector progress, individual collector states, regional results, last error, last published ID/time and scheduling state where available. These values help distinguish an active scan, a failed collector, a successful empty result and an incomplete regional scan.

Structured request logging includes request ID and HTTP route/status/duration. The `X-Request-ID` header supports log correlation. Sanitization is best effort; do not send secrets in request parameters or application fields.

## Metrics

`GET /metrics` provides Prometheus exposition. In production the route requires a `METRICS_TOKEN`, but the current Pydantic Settings class does not declare that setting; absent a code/config extension, production returns a disabled response. In development without a token, the endpoint is exposed. Keep it behind a restricted network boundary and do not assume a token can be configured until the deployed version supports it.

Review metric names/labels and access policy before long-term scraping; monitor cardinality and sensitive labels.

## Operations still needed

- Configure external alert delivery for stale scans, failed/partial regions, prolonged collector timeouts, lost scan locks, persistence errors, dependency degradation and API error rates.
- Define dashboard ownership, alert thresholds, escalation and incident procedures.
- Decide log/metric retention, regional storage and data residency.
- Exercise dependency outages, scan recovery, snapshot restoration and alert delivery during deployment rehearsal.
