# CloudScope Observability & Health Architecture

## 1. Overview
CloudScope implements the standard cloud-native observability pillars: health probes (Kubernetes liveness and readiness), diagnostic endpoints, Prometheus metrics, structured JSON logging, and correlation tracking.

## 2. Health & Readiness Probes

### `GET /live`
- **Purpose**: Kubernetes liveness probe.
- **Semantics**: Pure memory-only check. Returns HTTP 200 `{"status": "ALIVE"}` immediately.
- **Contract**: Never contacts external databases or AWS APIs. A failure indicates an unresponsive event loop or unhandled deadlock requiring container restart.

### `GET /ready`
- **Purpose**: Kubernetes readiness probe / load-balancer target healthcheck.
- **Semantics**: Checks local dependencies required for serving traffic:
  - Neo4j database connectivity
  - Redis cache connectivity
  - Durable relational database connectivity
- **Decoupled from AWS Availability**: Does **not** block on AWS STS or regional availability. Temporary AWS API throttling or outage does not cause healthy CloudScope instances to be marked unready.

### `GET /health/aws`
- **Purpose**: Diagnostic diagnostic probe for AWS credentials and regional connectivity.
- **Semantics**: Executes a fast `sts:GetCallerIdentity` call and returns identity ARN, account ID, and latency.

### `GET /health/dependencies`
- **Purpose**: Detailed diagnostic report on backend subsystem status.

### `GET /health`
- **Purpose**: General metadata probe returning Git commit hash, app version, build version, and startup time.

## 3. Prometheus Metrics (`GET /metrics`)
Exposes standard Prometheus exposition format telemetry:
- `cloudscope_http_requests_total{method, endpoint, status_code}`: Request counter.
- `cloudscope_http_request_duration_seconds{method, endpoint}`: Latency histogram.
- `cloudscope_scan_total{mode, status}`: Scan execution counter.
- `cloudscope_scan_duration_seconds{mode}`: Scan duration histogram.
- `cloudscope_rate_limit_exceeded_total{endpoint}`: Throttling counter.
- `cloudscope_copilot_requests_total{status}`: AI Copilot request counter.
- `cloudscope_copilot_latency_seconds`: AI Copilot latency histogram.

## 4. Structured JSON Logging & Correlation IDs (`X-Request-ID`)
- **Correlation ID Middleware**: Every incoming request is inspected for `X-Request-ID`. If absent, an ultra-unique `req-<timestamp>-<uuid>` is generated.
- **Context Propagation**: The correlation ID is placed in a Python `contextvars.ContextVar` and automatically injected into every log statement emitted during the request lifecycle.
- **Response Attachment**: The correlation ID is attached to the response header `X-Request-ID` and included in every structured error response body.
