# CloudScope Security Overview

CloudScope analyzes selected AWS inventory and IAM relationships. Deploy it only after the operator reviews authentication, AWS permissions, network exposure, storage protection and data handling. It is not a managed security service, complete AWS authorization engine or compliance certification.

## Authentication and authorization

Protected API routes use backend JWT/OIDC validation and route-level role dependencies. `DEV_AUTH_MODE` is only for an isolated local environment. Production IdP configuration, role claims, MFA, sessions, user lifecycle and identity recovery belong to the operator. Frontend route/button visibility does not enforce authorization. See [authentication](authentication.md) and [RBAC](rbac.md).

## AWS access

The backend's configured AWS profile/default credential chain determines the single account scanned by that deployment. Use a dedicated read-only principal with only required collection actions. IAM permissions on that principal are the actual AWS access boundary; CloudScope code is not a substitute for AWS IAM. Confirm the account and permissions independently. Separate accounts require separate deployment boundaries.

## Data and persistence

Users of one deployment share its account inventory and retained snapshots. User-owned simulation drafts have additional analyst scoping. SQL contains snapshots, finding lifecycle, audit and simulation records; Redis caches/coordinates; Neo4j stores graph topology. Protect databases, volumes, logs, exports and backups. Versioned migration, backup/restore and multi-worker recovery procedures remain open.

## Analysis assurance

- Static graph paths represent possible transitions under supported logic, not a proven intrusion.
- Action labels and risk findings come from CloudScope's evaluator and scoring model, not AWS policy evaluation output.
- Partial collectors, unsupported IAM semantics, conditions, resource policies, organization controls and runtime prerequisites can change real effective access.
- CloudTrail events show collected AWS activity; event coverage and intent are not guaranteed.
- Access Analyzer findings are an AWS evidence source, not proof that all exposure has been found.
- AI explanations are generated content and require source-evidence review.

## AI and secrets

Selected inventory/finding/path context may be sent to Gemini when an explanation is requested. Approve provider terms, retention, residency, minimization and consent before enabling it for sensitive data. Redaction helps but cannot guarantee all secret formats are removed. Never place credentials or secret values in tags, notes, policy descriptions, prompts or logs. See [secret management](secrets.md).

## Known production work

Independent security review, penetration testing, multi-tenant boundary review, versioned migrations, tested recovery, alert delivery, metrics access policy, large-account profiling, and exact-release hosted/deployment verification remain open. See [industry readiness](industry-readiness.md) and [security release checklist](security-release-checklist.md).
