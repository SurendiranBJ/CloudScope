# Industry Readiness Status

**Reviewed:** 2026-10-15
**Branch:** sura
**Assessment:** Useful security-analysis prototype; not production-certified.

This status describes the implementation and evidence available in this review. An implemented capability has not thereby passed independent security review, production-scale load testing, or a customer deployment rehearsal.

## Implemented foundations

| Area | Current implementation |
| --- | --- |
| AWS account projects | Owner-scoped project records, role verification with a generated per-project ExternalId, and manual scans through the selected verified role. |
| Project data scope | The UI sends the selected project with data requests. The API validates ownership, pins the selected snapshot, and avoids fallback to an unrelated global snapshot. Snapshots, scan runs, finding state/history, audit events, cache keys, and simulation drafts have project scope. |
| Durable simulation | What-if policy changes persist in SQL and are scoped to analyst identity and selected project. Simulation does not write to AWS. |
| Scan and snapshot lifecycle | Scan coordination uses Redis-backed lock leases where available; scan and snapshot metadata are persisted relationally; current snapshot reads are pinned per request. |
| Findings and evidence | Finding lifecycle state and history are persisted. Graph paths and findings expose evidence/provenance so static capability can be distinguished from observed activity. |
| User interface | Dashboard, Cloud Graph, Projects, Security Findings, Attack Paths, Policies, Resources, Alerts, Reports, and Settings are available. Attack Path groups are sorted by severity/risk and numbered in displayed order. |
| Optional AI explanations | The UI can request evidence-context explanations from the configured Gemini provider. Model output remains advisory and probabilistic. |

## Open work before production

1. Scheduled scans are not project-aware. The scheduler does not iterate verified account projects.
2. Complete the tenant-boundary review across data endpoints, background jobs, operational routes, exports, and error paths. Add adversarial cross-owner/project tests with production database/cache configuration.
3. Validate AWS temporary credential expiration and refresh during long scans and across worker restarts. Temporary credentials are cached in process memory; multi-worker deployment behavior requires explicit validation.
4. Adopt versioned database migrations. Current initialization uses create-all and ad hoc column migrations.
5. Test PostgreSQL, Redis, Neo4j, backup/restore, restart recovery, failover, and rollback using the target deployment.
6. Document supported IAM policy semantics and unsupported layers/condition keys. Profile large accounts and expose path truncation/completeness.
7. Add production alerting, incident procedures, retention/data residency controls, penetration testing, dependency/container review, and an independent security review.
8. Establish customer policy for AI context sent to the external provider, including consent, retention, and residency.
9. Verify hosted CI and deployment smoke-test evidence for the exact release commit.

## Milestone summary

Project registration, role verification, selected-project request scope, scoped persistence/cache keys, and durable simulation drafts are implemented and have focused regression coverage. This completes the code foundation for project-scoped manual analysis. Project-aware scheduling and deployment-specific isolation validation remain open, so the wider multi-account production milestone is not complete.
