# Industry Readiness Status

**Reviewed:** 2026-10-22
**Assessment:** Useful AWS security-analysis prototype; not production-certified.

CloudScope has implemented meaningful security workflows. They should not be mistaken for complete AWS coverage, verified effective access, enterprise tenant isolation, or a managed security service.

## Implemented foundations

| Capability | Current state |
| --- | --- |
| Account and credentials | One AWS account per deployment, selected by AWS credentials configured on the backend. Project onboarding and target-role selection are not offered in the UI. |
| AWS inventory | Collectors cover selected IAM, compute, storage, database, messaging, security and workflow services. See [phase3-architecture.md](phase3-architecture.md) for the current list and scope limits. |
| Region handling | Single-region, configured-region and global enabled-region modes; scans preserve attempted/successful/failed region metadata. |
| IAM analysis | Custom evaluator maps supported policy actions, resource scope, selected conditions, trust and workload transitions into evidence-bearing graph relationships. It does not equal the AWS authorization engine. |
| Attack paths | Bounded, risk-ranked possible paths and reachable-resource/blast-radius summaries. Current limits are six role hops and 200 emitted paths. |
| Runtime evidence | Selected CloudTrail activity and Access Analyzer findings can be included when permissions and regional coverage allow. |
| Finding workflow | Finding evidence and lifecycle state/history are persisted in SQL. |
| What-If Analysis | Multiple managed-policy attach/detach proposals for users, groups and roles; recomputes current/proposed analysis without AWS writes. Drafts persist by analyst identity. |
| Scan history | Durable snapshots include analysis and completeness/region metadata; retention defaults to ten. Historical UI is read-only. |
| Authentication | JWT/OIDC validation and server-side role dependencies; local development header mode is available only for isolated use. |
| Optional AI | Gemini-backed path/finding/alert explanations use selected evidence context and remain advisory. |
| UI | Dashboard, resources, Cloud Graph, Attack Paths, Findings, Policies, What-If, Saved Changes, Alerts, Reports and Settings. Both light and dark themes are supported. |

## Open work before production

1. Define deployment isolation and access controls for organizations that need multiple AWS accounts or tenants.
2. Replace ad hoc SQL schema compatibility changes with versioned migrations; test upgrades and restore.
3. Test PostgreSQL, Redis, Neo4j, backup/restore, worker restart, failover and rollback in target infrastructure.
4. Establish measurable collector coverage, throttling/backoff, long-running credential refresh and large-account scan duration.
5. Publish a tested IAM semantic matrix for resource policies, session policies, boundaries, SCPs, conditions, service-linked roles and service-specific behavior.
6. Expose clear path-count truncation and analysis completeness for large graphs.
7. Add production monitoring, alert delivery, retention/data residency controls, incident procedures, penetration testing and independent security review.
8. Approve AI provider context, data minimization, consent, retention and residency.
9. Tie full tests, hosted CI, deployment smoke tests and recovery rehearsal to a pinned release SHA.

## Account scope and legacy data

The current product workflow has one credential-selected account per deployment. Existing databases may retain old project tables and project-related columns because current SQL initialization does not delete legacy data. Those records do not make the Projects interface or multi-account scanning available. Separate accounts require separate deployments with independently configured credentials and storage.
