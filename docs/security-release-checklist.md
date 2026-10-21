# Security Release Checklist

This checklist is a pre-release work aid. A checked item requires evidence for the exact candidate build; no blanket PASS is implied by this document.

## Authentication and authorization

- [ ] Production identity-provider issuer, audience, signing keys, role claims, and login/session lifecycle tested end to end.
- [ ] Development header authentication disabled in deployed configuration.
- [ ] Every sensitive/mutating route has server-side authorization and rate limits appropriate to its cost.
- [ ] Authenticated-user scoping is reviewed for reads, writes, exports, AI context, and background jobs.
- [ ] Cross-user access tests pass against production-like PostgreSQL and Redis; deployment-wide AWS inventory sharing is explicitly understood.

## AWS and analysis safety

- [ ] Scanner principal has only approved read permissions.
- [ ] The backend credential identity and AWS account are confirmed in the deployed runtime.
- [ ] Credential expiration/refresh is tested during long scans and worker restart.
- [ ] Incomplete collection, unsupported IAM semantics, and path truncation are visible as uncertain/incomplete.
- [ ] Simulation confirmed not to issue AWS mutation calls.
- [ ] AI provider context, consent, retention, residency, and redaction policy reviewed.

## Persistence and recovery

- [ ] Versioned SQL migrations tested from all supported schema versions.
- [ ] Snapshot, finding, audit, and simulation state backups restored successfully.
- [ ] Redis outage, worker restart, lock recovery, and scan failure rehearsed.
- [ ] PostgreSQL and Neo4j production configuration reviewed.

## Release and operations

- [ ] Full backend and frontend suites pass on the exact release SHA.
- [ ] Hosted CI for the exact SHA is green.
- [ ] Production Compose/container smoke test passes.
- [ ] Monitoring, alert delivery, incident contacts, retention, and rollback documented.
- [ ] Independent security review completed.

Current open gaps are tracked in docs/industry-readiness.md and docs/release-readiness.md.
