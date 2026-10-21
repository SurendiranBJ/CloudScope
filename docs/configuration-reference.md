# CloudScope Configuration Reference

**Updated:** 2026-10-22
This reference is based on `backend/app/config.py`, `.env.example`, Compose files and the current frontend API client. Environment variables and `.env` values may override defaults. Inspect the resolved runtime environment and `docker compose ... config` for the deployment in use. Never print secrets while doing so.

## Runtime, authentication and browser access

| Setting | Backend default | Purpose and notes |
| --- | --- | --- |
| `ENVIRONMENT` | `development` | Exact `production` activates stricter auth and scan-lock checks. Compose may override it. |
| `AUTH_ENABLED` | `false` | Legacy/related flag; evaluate with `AUTH_REQUIRED`, `DEV_AUTH_MODE` and route dependencies. |
| `AUTH_REQUIRED` | `false` | Requires authentication outside production. Production always requires authentication. |
| `DEV_AUTH_MODE` | `false` | Enables local `X-Dev-Role` / `X-Dev-Subject` headers outside production. Never expose it to an untrusted network. |
| `JWT_SECRET` | empty | HMAC token verification secret. Supply a strong random value through secret injection. |
| `JWT_ALGORITHM` | `HS256` | Must match the trusted token issuer and accepted verifier configuration. |
| `OIDC_ISSUER_URL` | empty | Expected token issuer. Required by production configuration validation. |
| `OIDC_AUDIENCE` | empty | Expected token audience. Required by production configuration validation. |
| `OIDC_JWKS_URL` | empty | Optional key-set endpoint for asymmetric signature verification; use HTTPS in production. |
| `CORS_ORIGINS` | localhost origins | Allowed browser origins. Set exact UI origins in deployment; avoid wildcard origins for credentialed use. |
| `TRUSTED_PROXIES` | empty | Known proxy addresses used to trust forwarded client metadata. Set only the actual proxy layer. |
| `VITE_API_BASE_URL` | unset | Frontend build-time backend origin. When set, frontend requests append `/api/v1`; configure the value at build time. |

## AWS collection and regions

| Setting | Backend default | Purpose and notes |
| --- | --- | --- |
| `AWS_CREDENTIALS_DIR` | `~/.aws` | Host credential/config directory mounted read-only by development Compose. |
| `AWS_PROFILE` | `identityscope-scanner` | Named source profile. Compose defaults this to `default` unless overridden. If session construction with the named profile raises an exception, initialization attempts an SDK environment/default-chain fallback; confirm the actual identity with STS from the backend runtime. |
| `AWS_DEFAULT_REGION` | `ap-south-1` | Boto3 session/default region and fallback region. |
| `SCAN_REGIONS` | empty | Optional comma-separated fixed region list. Empty allows enabled-region discovery through EC2 `DescribeRegions`; a runtime single/global UI choice changes resolution. |

AWS permissions are determined by the backend principal's IAM policies. These values do not create or grant AWS permissions. The application scans the single AWS account returned by those credentials. See [AWS connection guide](../aws/templates/deployment_guide.md).

## SQL, graph, cache and scan coordination

| Setting | Backend default | Purpose and notes |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./cloudscope.db` | SQLAlchemy URL for durable snapshots and workflow records. SQLite is a local default. PostgreSQL is configurable but production upgrades/restores are not validated. |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` | Redis cache and scan coordination endpoint. Compose overrides to the Redis service hostname. Production scan coordination requires reachable Redis. |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt endpoint. |
| `NEO4J_USER` / `NEO4J_PASSWORD` | `neo4j` / `password` | Neo4j credentials. Replace defaults, isolate network access and inject secrets safely. |
| `SCAN_LOCK_LEASE_SECONDS` | `180` | Distributed scan lock lease; current worker heartbeat and recovery need deployment validation. |
| `SNAPSHOT_RETENTION_COUNT` | `10` | Number of old published snapshots retained by cleanup; history API returns at most ten. |
| `AUDIT_RETENTION_DAYS` | `90` | Audit-retention configuration. Confirm cleanup path and external retention requirements before relying on it. |

Relational schema setup currently uses table creation and compatibility column additions; it is not backed by a versioned migration framework. Legacy project schema fields may remain in old databases but do not provide active account selection in the UI.

## Server, scheduler and logs

| Setting | Backend default | Purpose and notes |
| --- | --- | --- |
| `BACKEND_PORT` | `8000` | Application port; Compose host mappings are configured separately. |
| `SCAN_INTERVAL_MINUTES` | `5` | Idle delay after a scan finishes before the next scheduled scan. The scanner waits for a terminal result before scheduling that delay. |
| `LOG_FORMAT` / `LOG_LEVEL` | `json` / `INFO` | Structured logging format and severity. Review log destinations and redaction. |
| `APP_VERSION` | `1.0.0` | Application version label. |
| `BUILD_VERSION`, `GIT_COMMIT`, `COMMIT_SHA`, `IMAGE_TAG` | unset | Optional build provenance values for diagnostics. |

## Rate limits

Feature limits use `RATE_LIMIT_<FEATURE>_MAX` and `RATE_LIMIT_<FEATURE>_WINDOW` seconds. Current defaults are scan `5/600`, Copilot `30/60`, simulation `30/60`, finding `60/60`, audit `60/60`, export `20/60`, and general `300/60`. Confirm storage behavior and proxy identity handling before treating these as a distributed abuse-control boundary.

## Optional AI provider

| Setting | Backend default | Purpose and notes |
| --- | --- | --- |
| `AI_PROVIDER` | `gemini` | Current supported provider selection. |
| `GEMINI_API_KEY` | unset | Server-side credential; optional if AI is disabled. Never expose in the frontend bundle. |
| `GEMINI_MODEL` | `gemini-3.8-flash` | Model identifier; confirm current provider availability and terms before deployment. |
| `GEMINI_FALLBACK_MODELS` | configured list | Candidate fallback model identifiers; validate current availability. |
| `AI_MAX_OUTPUT_TOKENS` | `4096` | Maximum generated output budget. |
| `AI_TEMPERATURE` | `0.2` | Provider generation setting. |
| `AI_CONTEXT_MAX_CHARS` | `24000` | Application context length cap, not a privacy filter. |
| `AI_TIMEOUT_SECONDS` | `30` | Provider call timeout. |

AI requests can transmit selected cloud inventory/finding/path context outside the deployment. Obtain data-handling approval before enabling it for sensitive data.

## Source of truth

Check `backend/app/config.py`, `.env.example`, `compose.yaml`, `compose.release.yaml`, `backend/app/security/config_validator.py` and the frontend build environment together. Confirm actual deployed values without copying credentials to logs or tickets.
