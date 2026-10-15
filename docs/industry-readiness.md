# Industry Readiness Work: Six Foundations

This checklist records code-backed work delivered for the current readiness milestone. A checked foundation means the capability exists in the repository; it does not imply certification, full AWS semantic coverage, or production validation.

## Delivered foundations

| Area | Current foundation |
| --- | --- |
| Finding confidence and workflow | Finding statuses are read from durable lifecycle state, and status changes are committed with append-only history before updated findings are exposed. Finding details show the transition timeline. |
| Explainable graph | Cloud Graph supports full inventory views and attack-path tracing. Attack paths and findings carry scan provenance and structured evidence; the UI offers evidence-grounded AI explanations. |
| Safer remediation | Remediation remains advisory. IAM change simulation produces impact previews without applying changes to AWS, and pending simulation drafts are isolated by authenticated issuer and subject. |
| Access control | The frontend can request a session profile whose identity and roles are derived by the backend after token validation. Simulation state is isolated per principal. API authorization remains authoritative. |
| Reliability | Snapshot publication persists before exposing the new snapshot. Cache clearing only deletes CloudScope-owned `v1:` Redis keys, and blast-radius errors or traversal truncation are represented as unknown/partial rather than low risk. |
| Release gates | CI's frontend dependency audit now fails the job on high-severity findings instead of ignoring audit failures. Existing test, lint, and production-build jobs remain in place. |

## Production gaps still open

- CloudScope still scans one configured AWS environment. It does not yet provide a project/account registry, AWS Organizations onboarding, per-account role assumption, or tenant isolation for snapshots, findings, scans, and audit data.
- Simulation drafts are principal-isolated but remain in process memory; they are not shared across backend workers or durable across restarts.
- The policy evaluator covers a documented subset of AWS authorization semantics. Its output must remain evidence-scoped and must not be represented as complete AWS IAM equivalence.
- AI explanations send selected scan context to the configured external model provider. Customer-configurable data residency, retention, and provider policies need to be established before broad enterprise deployment.
- OIDC/JWT role enforcement exists, but CloudScope does not itself provide enterprise SSO configuration, MFA enrollment, or customer-managed identity lifecycle.
- Production readiness still needs deployment-specific validation: PostgreSQL migration management, multi-worker/restart testing, backup restore drills, penetration testing, operational alerting, and a reviewed incident/support process.
- The local frontend linter currently reports warnings. Those should be resolved and the CI job made warning-free before treating lint as a release-quality gate.

## Next milestone

Build AWS account projects and tenant-aware persistence first. Do not enable shared customer hosting until account ownership is enforced at every read/write boundary and verified with cross-tenant isolation tests.
