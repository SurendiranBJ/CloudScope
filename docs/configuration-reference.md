# CloudScope Configuration Reference

This reference describes settings read by `backend/app/config.py` and important Compose overrides. Environment variables and `.env` values override application defaults. The direct backend, `compose.yaml`, and `compose.release.yaml` may resolve different values; inspect the final runtime environment and `docker compose ... config` before deployment. The repository `.env.example` is the local template, not a production secret store.

## Runtime, authentication, and browser access

| Setting | Application default | Function and deployment notes |
| --- | --- | --- |
| `ENVIRONMENT` | `development` | Runtime label. Exact `production` enables stricter auth and scan-lock behavior. |
| `AUTH_ENABLED` | `false` | Legacy/related auth switch. Review together with `AUTH_REQUIRED` and the actual route dependency behavior. |
| `AUTH_REQUIRED` | `false` | Requires authentication outside production. Production requires it regardless. |
| `DEV_AUTH_MODE` | `false` | Enables local dev identity headers outside production. Never enable in production or expose on untrusted networks. |
| `JWT_SECRET` | empty | HMAC verification secret. Supply a strong random secret through managed secret injection; do not commit it. |
| `JWT_ALGORITHM` | `HS256` | Token signature algorithm supported by verifier. Match the issuer configuration and do not accept weaker/unknown algorithms. |
| `OIDC_ISSUER_URL` | empty | Expected `iss` value; production validation requires a real issuer. |
| `OIDC_AUDIENCE` | empty | Expected token audience; production validation requires a configured value. |
| `OIDC_JWKS_URL` | empty | Optional JWKS endpoint for asymmetric verification. Must use HTTPS in production. |
| `CORS_ORIGINS` | localhost origins | Allowed browser origins. Set exact UI origins in deployment; never use a wildcard for a credentialed app. |
| `TRUSTED_PROXIES` | empty | Trusted proxy configuration used for client/request metadata. Set only known proxy addresses when deployed behind a proxy. |

## AWS collection and account projects

| Setting | Application default | Function and deployment notes |
| --- | --- | --- |
| `AWS_CREDENTIALS_DIR` | `~/.aws` | Host credential directory; Compose mounts it read-only for profile-based source credentials. |
| `AWS_PROFILE` | `identityscope-scanner` | Source profile used to establish AWS credentials. Compose may override this default. |
| `AWS_DEFAULT_REGION` | `ap-south-1` | Default AWS region for SDK/session behavior. |
| `SCAN_REGIONS` | empty | Optional comma-separated region override. Confirm effective region selection in the scan record. |
| Project `role_arn` | per project | Target account role assumed by manual project scans. Must be verified and trusted by the source AWS principal. |
| Project `external_id` | generated per project | STS ExternalId used on target role assumption. Install it in that role's trust policy; keep it private and scoped. |

AWS service access is governed by IAM policies attached to the actual source principal and target role. These configuration values do not grant AWS permissions. See [the AWS connection guide](../aws/templates/deployment_guide.md).

## SQL, graph, cache, and scan coordination

| Setting | Application default | Function and deployment notes |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./cloudscope.db` | SQLAlchemy URL for durable relational state. SQLite is a local default; production DB migration and restore are not yet proven. |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` | Redis endpoint for cache and scan coordination. Production coordination requires reachable Redis. |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt endpoint for graph storage. |
| `NEO4J_USER` / `NEO4J_PASSWORD` | `neo4j` / `password` | Neo4j credentials. Replace defaults, restrict network access, and inject secrets securely. |
| `SCAN_LOCK_LEASE_SECONDS` | `180` | Redis scan-lock lease duration. Validate heartbeat, expiry, and worker recovery under deployment conditions. |
| `SNAPSHOT_RETENTION_COUNT` | `10` | Configured snapshot retention count. Verify cleanup behavior and backup requirements before relying on it. |
| `AUDIT_RETENTION_DAYS` | `90` | Audit retention configuration. Confirm actual cleanup and external retention requirements. |

The scheduler is not project-aware. Do not infer project-specific scheduled scan behavior from global scan settings.

## Server, logs, and build metadata

| Setting | Application default | Function and deployment notes |
| --- | --- | --- |
| `BACKEND_PORT` | `8000` | Backend listener/application port; Compose can publish a host mapping separately. |
| `SCAN_INTERVAL_MINUTES` | `5` | Scheduled scan interval. Current scheduling does not iterate through registered projects. |
| `LOG_FORMAT` / `LOG_LEVEL` | `json` / `INFO` | Structured log encoding and severity threshold. Review log sinks and redaction. |
| `APP_VERSION` | `1.0.0` | Application version label. |
| `BUILD_VERSION`, `GIT_COMMIT`, `COMMIT_SHA`, `IMAGE_TAG` | unset | Optional build provenance fields for identifying the deployed artifact. |

## Rate limits

Each `RATE_LIMIT_<FEATURE>_MAX` is a request count and `RATE_LIMIT_<FEATURE>_WINDOW` is its window in seconds. Defaults: scan `5/600`, Copilot `30/60`, simulation `30/60`, finding `60/60`, audit `60/60`, export `20/60`, general `300/60`. Check the implementation's storage and proxy behavior before treating these as a distributed abuse-control boundary.

## Optional AI provider

| Setting | Application default | Function and deployment notes |
| --- | --- | --- |
| `AI_PROVIDER` | `gemini` | Provider selection; Gemini is the currently supported provider. |
| `GEMINI_API_KEY` | unset | Server-side credential; optional when AI features are not used. Do not expose to the frontend. |
| `GEMINI_MODEL` | `gemini-3.8-flash` | Model identifier; confirm availability and terms with the provider. Gemini 3+ uses thinking levels and ignores legacy sampling settings. |
| `GEMINI_FALLBACK_MODELS` | configured list | Candidate fallback model names. Verify current provider availability. |
| `AI_MAX_OUTPUT_TOKENS` | `4096` | Maximum generated output budget. |
| `AI_TEMPERATURE` | `0.2` | Sampling setting for model output. |
| `AI_CONTEXT_MAX_CHARS` | `24000` | Application context length cap; not a privacy filter. |
| `AI_TIMEOUT_SECONDS` | `30` | Provider request timeout. |

AI requests can transmit selected scan evidence to the external model provider. Apply the organization's data-handling and customer-consent policy before enabling it.

## Sources of truth

Check `backend/app/config.py`, `.env.example`, `compose.yaml`, `compose.release.yaml`, and `backend/app/security/config_validator.py` together. Confirm resolved values in the actual deployment without printing secrets into logs or tickets.
