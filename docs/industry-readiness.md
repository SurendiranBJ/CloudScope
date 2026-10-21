# Industry Readiness Status

**Reviewed:** 2026-10-15
**Branch:** sura
**Assessment:** Useful security-analysis prototype; not production-certified.

This status describes the implementation and evidence available in this review. An implemented capability has not thereby passed independent security review, production-scale load testing, or a customer deployment rehearsal.

## Implemented foundations

| Area | Current implementation |
| --- | --- |
| AWS account selection | One backend-configured AWS profile or default credential chain supplies the account scanned by the deployment. The Projects page and per-account role onboarding have been removed. Separate deployments are needed for separate AWS accounts. |
| Durable simulation | What-if policy changes persist in SQL and are scoped to analyst identity. Simulation does not write to AWS. |
| Scan and snapshot lifecycle | Scan coordination uses Redis-backed lock leases where available; scan and snapshot metadata are persisted relationally; current snapshot reads are pinned per request. |
| Findings and evidence | Finding lifecycle state and history are persisted. Graph paths and findings expose evidence/provenance so static capability can be distinguished from observed activity. |
| User interface | Dashboard, Cloud Graph, Security Findings, Attack Paths, Policies, Resources, Alerts, Reports, and Settings are available. Attack Path groups are sorted by severity/risk and numbered in displayed order. |
| Optional AI explanations | The UI can request evidence-context explanations from the configured Gemini provider. Model output remains advisory and probabilistic. |

## Open work before production

1. Define deployment separation and access controls for organizations that need multiple AWS accounts.
2. Adopt versioned database migrations. Current initialization uses create-all and ad hoc column migrations; legacy project columns remain for compatibility with existing data.
3. Test PostgreSQL, Redis, Neo4j, backup/restore, restart recovery, failover, and rollback using the target deployment.
4. Document supported IAM policy semantics and unsupported layers/condition keys. Profile large accounts and expose path truncation/completeness.
5. Add production alerting, incident procedures, retention/data residency controls, penetration testing, dependency/container review, and an independent security review.
6. Establish customer policy for AI context sent to the external provider, including consent, retention, and residency.
9. Verify hosted CI and deployment smoke-test evidence for the exact release commit.

## Milestone summary

The application uses one AWS account per deployment, selected by credentials configured on the backend. Existing project data is retained in storage for compatibility, but project selection is no longer available or used for scanning. The wider multi-account production milestone is not part of the current product workflow.
