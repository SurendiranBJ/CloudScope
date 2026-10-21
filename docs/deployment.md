# CloudScope Deployment Guide

## Deployment options

- **Development Compose:** builds the backend/frontend from this checkout and starts Neo4j and Redis. See compose.yaml.
- **Release Compose:** pulls prebuilt GHCR images and requires production OIDC configuration. See compose.release.yaml.

The release configuration has not been runtime-validated as part of the 2026-10-15 review. Do not expose a deployment to customer data until its authentication, network, storage, restore, and monitoring settings are reviewed.

## Local development with Compose

1. Copy .env.example to .env.
2. Choose local-only settings: ENVIRONMENT=development, AUTH_ENABLED=false, AUTH_REQUIRED=false, DEV_AUTH_MODE=true. Set a strong NEO4J_PASSWORD and a non-placeholder JWT_SECRET.
3. Set AWS_PROFILE and AWS_CREDENTIALS_DIR to a profile with only the collection permissions you need. The Compose mount is read-only. CloudScope scans the account returned by this configured credential source.
4. Start from the repository root: docker compose -f compose.yaml up --build
5. Open http://localhost:8080. The backend is exposed on localhost:8000.

The Compose development file includes local development defaults; do not use DEV_AUTH_MODE or placeholder values outside an isolated workstation.

## Release Compose

1. Configure an OIDC issuer and audience, a strong JWT secret, Neo4j credentials, and the approved AWS credential source. Configure a supported DATABASE_URL for your deployment.
2. Set the release IMAGE_TAG to an existing image tag. The default rolling sura-latest tag is not an immutable release pin.
3. Review network exposure, persistent volumes, backups, monitoring, and secret injection.
4. Run docker compose -f compose.release.yaml config and review the resolved configuration.
5. Pull and start the reviewed image: docker compose -f compose.release.yaml pull; docker compose -f compose.release.yaml up -d
6. Validate liveness/readiness, login/token flow, the configured account identity, manual scans, backup restore, and rollback before use.

The release compose file enables required OIDC/JWT authentication and disables development headers. A valid production IdP and role claims must be configured; container startup alone does not prove users can authenticate.

## Ports and services

The development Compose stack exposes the frontend at 8080 and backend at 8000 on the host. Neo4j HTTP/Bolt are bound to loopback in development. Redis has no host port mapping. The release stack exposes the frontend at 8080 and keeps backend/Redis/Neo4j on internal Compose networks.

## Data and credentials

- SQL database: SQLite by default in the Compose volume; PostgreSQL can be configured through DATABASE_URL, but a production migration/restore rehearsal is still required.
- Redis: scan lock coordination and cache. Production readiness depends on reachable Redis.
- Neo4j: graph storage; readiness checks dependencies.
- AWS credentials: mounted read-only for profile-based collection, or supplied through the AWS SDK credential chain. The deployment scans the single account identified by those credentials.
- Gemini: optional. AI requests send selected scan context to the configured external provider.
