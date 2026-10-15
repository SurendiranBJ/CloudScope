# CloudScope: Current Audit and Change Summary

**Updated:** 2026-10-15
**Branch:** sura

This file summarizes the current implementation represented by the working tree. It is not an independent security certification. Older claims and metrics that were not revalidated are historical; use the current audit and release-readiness documents for present status.

## Current implementation areas

- **Projects and AWS accounts:** owner-scoped project records, cross-account role verification with a generated ExternalId, selected-project request context, project-scoped snapshots and scan runs, and manual scans through the selected verified role.
- **Durable analysis state:** project-scoped finding lifecycle/history, audit records, cache keys, and SQL-backed simulation drafts.
- **Simulation safety:** policy changes are analyzed as what-if state only; simulation does not apply IAM changes to AWS.
- **Graph and attack-path UX:** Cloud Graph relationship labels remain visible; the dashboard separates its title and controls toolbar; Attack Path groups are sorted by severity/risk and sequentially numbered in the filtered view.
- **Scan lifecycle UX:** elapsed time normalizes backend ISO timestamps with an offset and trailing Z and continues across status polling.
- **Verification:** the final local backend suite passed (555/555), frontend tests passed (33/33), TypeScript/production build passed, and lint exited 0 with warnings. See docs/final-verification.md for exact scope and remaining CI/deployment gaps.

## Current limitations

- Scheduled scans do not yet iterate over registered projects.
- Project isolation, credential refresh/expiry behavior, database migrations, and production recovery need deployment-backed tests and independent review.
- IAM evaluation, risk scoring, path enumeration, and CloudTrail correlation have coverage limits; none is a complete AWS authorization or threat-detection engine.
- External AI explanations are advisory and send selected context to the configured provider.
- Hosted CI for the final commit has not been established. Full local backend and frontend checks are green for the reviewed working tree; release SHA verification and deployment checks remain necessary.

## Historical records

Earlier page-by-page UI audits, real-AWS counts, and release statements reflect earlier code states. Use README.md, docs/final-audit.md, and docs/release-readiness.md for current claims.
