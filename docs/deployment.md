# CloudScope Deployment Guide

**Updated:** 2026-10-22
This guide describes repository Compose configurations. Neither production Compose nor production recovery has been exercised in the current review.

## Deployment choices

- **Local source development:** run FastAPI and Vite separately, or use `compose.yaml` to build source plus Redis and Neo4j.
- **Release Compose:** `compose.release.yaml` pulls prebuilt images. Pin a reviewed immutable `IMAGE_TAG` and configure production authentication and secrets.

One deployment scans the AWS account identified by credentials configured on the backend. The application does not expose Projects or account-role onboarding. Separate AWS accounts require separate backend deployments and independent state/storage boundaries.

## Run from source on a workstation

1. Configure AWS credentials for the backend process. Check the identity with `aws sts get-caller-identity` using the same profile.
2. From `backend`, install `requirements.txt` and `requirements-dev.txt`, then start `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.
3. From `frontend`, run `npm ci`, then `npm run dev -- --host 127.0.0.1`.
4. Open `http://127.0.0.1:5173/`; API docs are at `http://127.0.0.1:8000/docs`.
5. Configure an isolated development authentication mode deliberately. Do not expose dev headers or disable authentication on a network shared with untrusted users.

The backend starts scheduled scan processing at application startup and requests an initial scan. Without AWS credentials, startup can succeed while AWS collectors fail. Observe scan status before treating data as representative.

## Local Docker Compose

1. Copy `.env.example` to `.env`.
2. For an isolated workstation only, set explicit local values such as `ENVIRONMENT=development`, `AUTH_REQUIRED=false`, and `DEV_AUTH_MODE=true`. Use strong local database passwords and do not expose development ports to an untrusted network.
3. Set `AWS_PROFILE` and `AWS_CREDENTIALS_DIR` to the intended read-only profile. Docker mounts the credential directory read-only. Ensure the named profile exists inside the container.
4. Start the stack from the repository root:

   ```bash
   docker compose -f compose.yaml up --build
   ```

5. Open `http://localhost:8080`; backend API docs are at `http://localhost:8000/docs`.

The frontend is published on host port 8080. Backend port 8000 and Neo4j console/Bolt are bound to loopback by the development Compose file; Redis has no host port mapping. Persistent volumes hold Neo4j data/logs, Redis data and application SQL storage.

## Release Compose preparation

Before starting a production-like stack:

1. Configure production OIDC issuer/audience/JWT verification and disable `DEV_AUTH_MODE`.
2. Replace placeholder secrets; use a managed secret injection mechanism and secure Neo4j authentication.
3. Configure the AWS credential source for one intended account and verify its IAM permissions are read-only.
4. Pin `IMAGE_TAG` to an immutable reviewed image digest/tag. The rolling `sura-latest` default is not a release pin.
5. Choose and validate the SQL URL and durable volume/backup plan. Schema upgrade/restore is not currently proven.
6. Review proxy/TLS/CORS, ports, network boundaries, observability and AI data handling.
7. Inspect resolved configuration:

   ```bash
   docker compose -f compose.release.yaml config
   ```

8. After an approved change window, pull/start the reviewed artifact and validate liveness/readiness, authentication, AWS identity, manual/scheduled scans, snapshots, backups and rollback.

Container startup alone does not prove successful user login, AWS scan coverage, data recovery or production readiness.

## Service and data boundaries

| Service | Role | Persisted state / exposure notes |
| --- | --- | --- |
| Frontend | React app served by a web container or Vite in development | Browser session and frontend build-time API base. Keep backend origin and TLS consistent. |
| Backend | FastAPI API, scan scheduler/coordinator, AWS collectors and analysis | SQL application data, configured AWS credentials, Redis/Neo4j access. Secure logs and admin routes. |
| SQL | Durable snapshots, findings, audit and simulation drafts | Compose defaults to SQLite in an application volume. Production PostgreSQL may be configured but migration/restore is unverified. |
| Redis | Cache and distributed scan lock/coordination | Not authoritative snapshot storage. Production scans require working coordination. |
| Neo4j | Graph persistence and loading | Restrict Bolt/HTTP access and back up graph data. |
| Gemini | Optional external explanation provider | Receives selected scan context from backend; needs data governance approval. |

For exact variables see [configuration reference](configuration-reference.md); for backup, scan and health procedures see [operations](operations.md).
