# CloudScope Current Repository Audit

**Review date:** 2026-10-22
**Scope:** Source and documentation state in the current local workspace. This is a code/documentation review, not a penetration test, AWS certification, or production approval.

## Executive assessment

CloudScope has a working AWS collection and analysis pipeline, graph and attack-path views, finding workflows, persisted scan history, multi-change IAM policy simulation, and optional AI explanations. The product is best described as a security-analysis prototype. It is not production-certified or a comprehensive AWS authorization engine.

## Component status

| Area | Assessment | Current implementation and limits |
| --- | --- | --- |
| AWS account scope | Single configured account per deployment | Backend credentials select the scanned account. Project/account onboarding is not exposed in the UI. Legacy project tables/fields may remain for compatibility. |
| AWS collection | Implemented for a selected service set | Sixteen status groups cover IAM, EC2, S3, Lambda, Secrets Manager, RDS, DynamoDB, ECS, ECR, CodeCommit, grouped extended services, Access Analyzer and CloudTrail. Service and regional permissions can make results partial. |
| IAM analysis | Implemented with semantic limits | Custom policy/trust evaluation produces action evidence, reachability and risk signals. It does not model every AWS policy layer, condition key or service-specific authorization rule. |
| Graph and attack paths | Implemented with traversal bounds | NetworkX analysis and graph views model selected identity, role, workload, policy and resource transitions. Six-hop role traversal and a 200-path output cap can omit deeper or lower-ranked results. |
| Runtime activity | Implemented with source limits | Selected CloudTrail events and Access Analyzer findings are collected where available. Event absence is inconclusive; an event is not itself proof of malicious intent. |
| Findings | Implemented with workflow state | Findings have evidence and persisted lifecycle/history. Multi-store failures and high-volume reconciliation need deployment-backed testing. |
| What-If Analysis | Implemented for a defined change set | Users, groups and roles can receive managed-policy attach/detach proposals. Multiple changes are analyzed together; drafts persist by analyst. No AWS mutation is performed. |
| Snapshot history | Implemented, capped | Published snapshots include full analysis collections and region/completeness metadata. Default retention is ten. Restore/upgrade behavior needs production rehearsal. |
| Authentication/RBAC | Implemented with deployment dependencies | JWT/OIDC verification and server-side route guards exist. Production IdP/session lifecycle, role claims and MFA are operator responsibilities. |
| AI explanations | Optional | Gemini receives selected scan context. Output is generated and advisory; provider governance and data policy must be approved. |
| Persistence and coordination | Implemented with operational risk | SQL stores snapshots/workflows; Redis coordinates/cache; Neo4j stores graph topology; NetworkX performs in-process analysis. SQL schema changes are not managed by a versioned migration system. |
| Theme/UI | Implemented | Shared enterprise color tokens cover light and dark surfaces; graph labels/backgrounds respond to theme changes. Visual browser review was not part of the current documentation pass. |
| Release and production operations | Not verified | Local build and targeted checks do not prove hosted CI, production Compose, backups, database upgrade, scale, alert delivery, or rollback. |

## Verification evidence

- Frontend production and TypeScript build passed on 2026-10-22.
- Frontend lint exited 0 on 2026-10-22 with non-blocking warnings, including existing Fast Refresh and a hook-dependency warning in `SnapshotViewContext`.
- Focused backend tests passed 47/47 on 2026-10-21 for snapshot consistency, AI provider behavior, APIs and audit logging.
- Frontend tests last passed 33/33 on 2026-10-21, before the latest theme source changes.
- The full scanner/snapshot test group was interrupted before completion. The full backend suite and hosted CI for the current workspace were not verified.
- No fresh real-AWS run, production deployment exercise, backup restore, migration upgrade or independent security review was performed for this review.

## Priority work before production use

1. Establish production identity-provider provisioning, session lifecycle, authorization tests and deployment isolation.
2. Replace ad hoc SQL schema upgrades with versioned migrations and exercise upgrade, backup, restore and rollback.
3. Measure collector completeness, API throttling, regional timeouts, large-account performance and path truncation.
4. Maintain explicit supported/unsupported IAM semantics and validate high-impact decisions in AWS.
5. Harden production metrics and diagnostic endpoint access; add alert delivery, incident ownership and retention controls.
6. Approve AI provider data handling, customer consent, retention and residency.
7. Run the complete backend/frontend suites, hosted CI, production-like deployment tests and independent security review against one pinned release SHA.

## Caveat

Assessment describes implemented code paths and recorded checks only. It does not guarantee that every account, service, policy, deployment or failure mode is fully covered. Read [industry readiness](industry-readiness.md) and [release readiness](release-readiness.md) before making a deployment decision.
