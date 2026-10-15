# CloudScope Security Overview

## Security model

CloudScope is a security analysis prototype that should be deployed only after the operator configures identity, network boundaries, database credentials, AWS permissions, and data retention. It is not a managed security service or a compliance certification.

## Authentication and roles

Protected APIs use backend JWT/OIDC validation and role dependencies when authentication is required. DEV_AUTH_MODE is for local development only. Frontend role visibility is user experience; backend authorization is the actual control. Production IdP provisioning, claim mapping, session lifecycle, and MFA policy are deployment responsibilities.

## AWS access

Use a dedicated read-only AWS principal. Project role verification uses an ExternalId and selected project role for manual scans. CloudScope code is not a substitute for IAM restrictions. Scheduled scans are not yet project-aware.

## Data isolation and storage

Project ownership and project context scope account data and durable simulation drafts. Snapshots, scan runs, findings, audit events, and cache keys include project scope. This implementation has focused tests but has not been independently reviewed across every endpoint/background job or validated at production scale. Do not enable shared customer hosting based only on these controls.

SQL holds durable app state; Redis coordinates and caches; Neo4j holds graph data. Protect all stores and backups. Schema upgrades, cross-worker recovery, and restore behavior need deployment rehearsal.

## AI and secrets

Optional AI explanations transmit selected scan context to the configured Gemini provider. Obtain approval for provider data handling and customer consent. The sanitizer is best effort; never put secrets in application fields or logs.

## Known security limitations

- The IAM evaluator does not model every AWS authorization layer or condition key.
- CloudTrail coverage depends on collection configuration, region availability, and event limits.
- External model output is probabilistic.
- Metrics and diagnostic routes need deployment-level network review.
- Penetration testing, independent tenant isolation review, and incident-response validation remain open.
