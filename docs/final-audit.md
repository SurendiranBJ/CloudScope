# CloudScope Current Repository Audit

**Review date:** 2026-10-15
**Branch:** sura
**Scope:** Current working tree, including uncommitted source changes reviewed for this documentation pass. This is a code review summary, not a penetration test or production certification.

## Executive assessment

CloudScope has meaningful AWS collection, graph analysis, finding workflow, simulation, and user-interface capabilities. AWS scanning uses the single credential source configured for the backend. Several important production requirements remain open. Do not describe this revision as fully industry-ready or production-certified.

## Component status

| Area | Assessment | Current evidence and limitations |
| --- | --- | --- |
| AWS collection | PARTIAL | Boto3 collectors cover selected IAM and resource services and regions. Permission failures and supported service coverage need broader field-level completeness validation. Configure the AWS principal as read-only. |
| IAM authorization | PARTIAL | A custom evaluator handles supported policy constructs and evidence. It is not the complete AWS authorization engine; boundaries, session policies, SCPs, resource policies, conditions, and service-specific context require explicit coverage tests. |
| Graph and attack paths | IMPLEMENTED WITH LIMITS | Identity/resource graph, evidence-bearing relationships, path ranking, and UI tracing are present. Traversal is bounded and may omit paths at scale; static capability is not proof of exploitation. |
| Findings | IMPLEMENTED WITH LIMITS | SQL-backed finding status/history and transitions exist. Reconciliation and multi-store consistency require deployment-backed failure testing. |
| AWS account selection | SINGLE CONFIGURED ACCOUNT | The Projects interface, API, and target-role assumption flow are removed. Scans use the backend's configured AWS profile/default credential chain. Use separate deployments for separate accounts. |
| Simulation | IMPLEMENTED | Drafts persist in SQL and are scoped by principal. The what-if engine does not apply changes to AWS. Policy evaluation accuracy remains subject to evaluator limits. |
| Snapshot and SQL state | IMPLEMENTED WITH MIGRATION RISK | Relational snapshots, scan records, audit records, and restart recovery exist. Schema initialization still uses create-all/ad hoc migrations rather than a versioned migration process. |
| Redis and scan lock | IMPLEMENTED WITH DEPLOYMENT LIMITS | Redis lease/heartbeat coordination exists and production lock acquisition fails closed when Redis is unavailable. Multi-worker failure and recovery need deployment testing. |
| Authentication and RBAC | IMPLEMENTED WITH CONFIGURATION DEPENDENCE | JWT/OIDC validation and server-side route guards exist; development header auth is intended only for local development. Production IdP provisioning/login and customer lifecycle remain deployment concerns. |
| AI explanations | IMPLEMENTED, OPTIONAL | Gemini-backed evidence-context answers are available. Output is probabilistic and selected scan context is sent to the configured external provider. |
| Operations and observability | PARTIAL | Health/readiness, structured logs, request IDs, metrics, and operations endpoints exist. Alerting, retention, metrics access policy, and incident procedures need review. |
| Release/deployment | NOT VERIFIED | Local build/tests do not prove Docker production startup, hosted CI, migration upgrade, backup restore, or rollback. |

## Verification evidence for this review

- Backend full suite: 564 passed, 0 failed in 395.11 seconds. The prior `datetime.utcnow()` warnings are removed; two external dependency warnings remain.
- Frontend test suite: 33 passed, 0 failed.
- Frontend TypeScript/production build: passed.
- Full frontend lint: exit code 0; Oxlint reports 13 non-blocking Fast Refresh export warnings. Hook dependency warnings were corrected.
- Python compile and Git whitespace checks passed.
- No hosted GitHub Actions result, fresh real-AWS scan, production Compose rehearsal, or independent security review was verified for the final change set.

## Priority open findings

### Release blockers

1. Define deployment separation and access controls for organizations that need multiple AWS accounts.
2. Verify temporary AWS credentials expire/refresh safely during long scans and across worker restarts.
3. Replace ad hoc schema alteration with versioned migrations; exercise upgrade, backup, and restore.
4. Record supported and unsupported IAM semantics. Do not imply complete effective-access or threat-detection coverage.
5. Run full tests, hosted CI, production deployment smoke tests, and rollback/restore rehearsal for the exact release SHA.
6. Establish independent security review, AI data handling policy, alerting, and incident procedures before shared hosting.

## Review caveat

This audit describes implementation state, not a guarantee that every API operation, AWS account, database failure mode, or production deployment behaves correctly. See industry-readiness.md and release-readiness.md for the milestone and gate.
