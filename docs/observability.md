# Observability and Health

CloudScope includes basic health probes, structured request logs, request IDs, Prometheus metrics, and operations endpoints. These components are diagnostic building blocks, not a complete monitoring or alerting service.

## Health endpoints

- GET /live: process liveness check; does not validate AWS availability.
- GET /ready: checks relational database, Redis, and Neo4j connectivity.
- GET /health: application/build metadata.
- GET /health/aws: AWS identity/connectivity diagnostic; admin protected.
- GET /health/dependencies: dependency diagnostics. Confirm route authorization before exposure.

Readiness is intentionally distinct from AWS availability; a regional AWS outage should not necessarily restart an otherwise healthy API process. However, scan operations still require functioning AWS credentials and APIs.

## Metrics and logs

Prometheus metrics are served at /metrics. Restrict access through network policy/reverse proxy until an explicit access policy is configured. Review metric labels for cardinality before long-term production retention.

Structured logs and the X-Request-ID response header support request correlation. Sanitization is best effort; never intentionally log credentials, tokens, or secret values.

## Production work still required

Set up alert delivery for stale scans, scan failures/partial regions, Redis/database/Neo4j degradation, persistence errors, lock contention, and API error rates. Define retention, dashboards, escalation, ownership, and incident procedures. Test alerts and recovery during a deployment rehearsal.
