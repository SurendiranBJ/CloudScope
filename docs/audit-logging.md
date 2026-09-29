# CloudScope Administrative Audit Logging

## 1. Overview
CloudScope records a tamper-evident, durable audit trail of all sensitive operations performed by authenticated users and internal background tasks. Audit logging ensures enterprise compliance (SOC 2, ISO 27001, FedRAMP).

## 2. Audited Actions
The audit service (`backend/app/services/audit/audit_service.py`) automatically captures:
- `SCAN_TRIGGERED`: Manual or scheduled AWS scan initiation (captures scan mode, target regions).
- `REGION_CONFIGURATION_CHANGED`: Alteration of single vs global regional discovery.
- `FINDING_MUTATED`: Finding status updates (`ACKNOWLEDGED`, `SUPPRESSED`, `RESOLVED`, reason).
- `SIMULATION_EXECUTED`: What-if policy mutation simulations.
- `COPILOT_REQUESTED`: AI Copilot natural language queries and token telemetry.
- `SETTINGS_UPDATED`: System configuration changes.

## 3. Automated Secret Redaction
Before any audit event is committed to durable storage:
- All dictionary keys and string values are passed through `backend/app/utils/sanitizer.py`.
- Any sensitive keys (`password`, `secret`, `token`, `api_key`, `access_key`, `credential`) are masked with `[REDACTED]`.
- AWS Access Keys (`AKIA...`), AWS Secret Keys, Session Tokens, and Gemini API keys (`AIza...`) are automatically detected and masked.

## 4. Querying the Audit Trail API
- Endpoint: `GET /api/v1/audit`
- Authorization: Restricted to `SECURITY_OFFICER` and `ADMINISTRATOR` roles.
- Rate Limiting: Sliding window rate limited (default: 60 requests/minute per principal).
- Query Parameters:
  - `actor_id`: Filter by actor user ID
  - `action`: Filter by action name (e.g. `SCAN_TRIGGERED`)
  - `resource_type`: Filter by resource type (e.g. `finding`, `simulation`)
  - `resource_id`: Filter by resource identifier
  - `scan_id`: Filter by scan execution ID
  - `limit`: Max records to return (1 - 200, default: 50)
  - `offset`: Pagination offset

## 5. Retention Policy
The default audit log retention period is 90 days (`AUDIT_RETENTION_DAYS=90`). Records older than the retention threshold are safely pruned during routine database maintenance.
