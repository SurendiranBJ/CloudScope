# CloudScope Canonical Configuration Reference

## Core Application Settings
| Variable | Purpose | Required? | Default | Secret? |
| :--- | :--- | :---: | :--- | :---: |
| `ENVIRONMENT` | Operating environment (`development` or `production`) | No | `development` | No |
| `LOG_LEVEL` | Application logging verbosity | No | `INFO` | No |
| `APP_VERSION` | Application version identifier | No | `development` | No |
| `BACKEND_PORT` | Port for the backend API | No | `8000` | No |
| `SCAN_INTERVAL_MINUTES`| Periodic interval for scheduled scans | No | `5` | No |

## Authentication & Security (MANDATORY IN PRODUCTION)
| Variable | Purpose | Required? | Default | Secret? |
| :--- | :--- | :---: | :--- | :---: |
| `AUTH_ENABLED` | Enables JWT/OIDC authentication | **Yes (Prod)** | `false` | No |
| `AUTH_REQUIRED` | Requires valid identity on protected routes | **Yes (Prod)** | `false` | No |
| `DEV_AUTH_MODE` | Allows local `X-Dev-Role` header auth bypass | No | `false` | No |
| `JWT_SECRET` | Cryptographic secret for signing/validating HS256 JWTs | **Yes (Prod)** | *None* | **Yes** |
| `JWT_ALGORITHM` | Algorithm for token verification | No | `HS256` | No |
| `OIDC_ISSUER_URL` | Trusted OIDC issuer for token validation | **Yes (Prod)** | *None* | No |
| `OIDC_AUDIENCE` | Expected audience claim for token validation | **Yes (Prod)** | *None* | No |
| `OIDC_JWKS_URL` | HTTPS endpoint for asymmetric key retrieval | No | *None* | No |
| `CORS_ORIGINS` | Comma-separated list of allowed CORS origins | No | `http://localhost:5173,...` | No |

## AWS Integration
| Variable | Purpose | Required? | Default | Secret? |
| :--- | :--- | :---: | :--- | :---: |
| `AWS_PROFILE` | Named AWS credentials profile for local mode | No | `identityscope-scanner` | No |
| `AWS_DEFAULT_REGION`| Primary AWS region for analysis | No | `ap-south-1` | No |
| `SCAN_REGIONS` | Comma-separated list of additional regions | No | *Empty* | No |
| `AWS_CREDENTIALS_DIR`| Host mount path for `.aws` directory | No | `~/.aws` | No |

## Storage & Database
| Variable | Purpose | Required? | Default | Secret? |
| :--- | :--- | :---: | :--- | :---: |
| `NEO4J_URI` | Connection string for Neo4j graph database | No | `bolt://neo4j:7687` | No |
| `NEO4J_USER` | Neo4j authentication username | No | `neo4j` | No |
| `NEO4J_PASSWORD` | Neo4j authentication password | **Yes (Prod)** | *None* | **Yes** |
| `REDIS_HOST` | Hostname of the Redis coordination cache | No | `redis` | No |
| `REDIS_PORT` | Port of the Redis service | No | `6379` | No |
| `DATABASE_URL` | Connection string for the persistent SQL DB | No | `sqlite:////app/storage/cloudscope.db`| No |

## AI / Copilot Integration
| Variable | Purpose | Required? | Default | Secret? |
| :--- | :--- | :---: | :--- | :---: |
| `AI_PROVIDER` | AI backend engine (`gemini` only) | No | `gemini` | No |
| `GEMINI_API_KEY` | API Key for Google Gemini services | If AI Enabled | *None* | **Yes** |
| `GEMINI_MODEL` | Primary Gemini model version | No | `gemini-2.5-flash` | No |
| `AI_MAX_OUTPUT_TOKENS`| Limit on generated AI response tokens | No | `4096` | No |
| `AI_TEMPERATURE` | Generation randomness/temperature | No | `0.2` | No |
| `AI_CONTEXT_MAX_CHARS`| Truncation limit for prompt context injection | No | `24000` | No |
| `AI_TIMEOUT_SECONDS`| Maximum duration for an AI API request | No | `30` | No |

## Production Deployment & Validation
- **Configuration Validation**: Handled by `backend/app/security/config_validator.py`.
- In a production environment (`ENVIRONMENT=production`):
  - `AUTH_ENABLED` and `AUTH_REQUIRED` must be `true` (enforced via `compose.release.yaml`).
  - `DEV_AUTH_MODE` must be `false`.
  - `JWT_SECRET` must be at least 32 characters (or `OIDC_JWKS_URL` provided) and not a weak placeholder.
  - `NEO4J_PASSWORD` must not be a default weak placeholder (`password`, `admin`, etc.).
  - `OIDC_ISSUER_URL` and `OIDC_AUDIENCE` must be present.
