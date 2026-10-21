# CloudScope: Current Audit and Change Summary

**Documentation date:** 2026-10-22
**Repository branch:** `sura`
**Purpose:** Describe the current product workflow and recorded verification. This is not an independent security assessment or a production approval.

## Current product model

CloudScope is a single-configured-account AWS security analysis application. The backend's AWS profile/default credential chain identifies the account scanned by a deployment. The Projects UI and per-account AssumeRole onboarding are absent. Legacy project schema and internal scope fields may still exist for database compatibility; they are not a supported account-selection workflow.

The application collects selected AWS identity, policy, resource, Access Analyzer and CloudTrail data; builds graph relationships; evaluates a supported subset of IAM semantics; and presents risk, findings, possible paths, observed events, reports and scan provenance. It includes a multi-change managed-policy what-if workflow for users, groups and roles. Simulation drafts do not invoke AWS mutation APIs.

## Recent implementation and documentation areas

- AWS collection includes IAM users/groups/roles/policies, EC2, S3, Lambda, Secrets Manager, RDS, DynamoDB, ECS, ECR, CodeCommit, SQS, SNS, customer-managed KMS keys, EKS, Step Functions, Access Analyzer and selected CloudTrail events.
- Scan results retain status, scan/snapshot IDs, timestamps, region outcomes and collection completeness. The UI exposes up to ten retained snapshots and permits read-only historical browsing.
- Candidate attack paths are constrained by allowed relationship types, policy/action evidence and guarded workload pivot rules. Path enumeration is bounded to six role hops and 200 emitted paths.
- Attack path groups are sorted and sequentially numbered in the displayed filtered list. Cloud Graph and Attack Paths use theme-aware surfaces and graph labels in light and dark mode.
- Simulation supports adding/removing multiple managed policies, saving/editing drafts, comparing current and proposed graph/risk/reachability/path data, and resetting the draft.
- AI explanations are optional, Gemini-backed and advisory. Selected evidence context is sent to the configured provider.
- Documentation now describes the application purpose, architecture, data scope, evidence semantics, simulation boundaries, operations and verification status consistently.

## Verification status recorded for this workspace

- Frontend production build and TypeScript build passed on 2026-10-22 after the theme updates.
- Frontend lint exited successfully on 2026-10-22 with non-blocking Fast Refresh and existing hook dependency warnings elsewhere in the repository.
- `git diff --check` passed before documentation edits; rerun after final edits if a clean whitespace check is needed.
- A focused backend set passed 47 tests on 2026-10-21: published snapshot consistency, AI provider, API endpoints and audit logging.
- Frontend unit tests last passed 33/33 on 2026-10-21, before the latest theme changes.
- The complete scanner/snapshot regression group was not completed in the latest attempt. The full backend suite, hosted GitHub Actions run for the current workspace, fresh AWS scan, production Compose deployment and recovery rehearsals are not verified here.

See [final verification](docs/final-verification.md) for scope and caveats.

## Known limitations

- CloudScope covers a selected set of AWS services; it is not an all-services scanner.
- The custom evaluator does not reproduce every AWS policy layer, condition, service behavior, or authorization decision.
- A graph path is a model-derived possibility, not proof of exploitability or compromise. CloudTrail correlation depends on available events and scan coverage.
- Global scans can be slow. Service permissions, regional availability and API timeouts may produce partial results.
- SQL initialization uses table creation and compatibility column additions rather than a versioned migration framework. Production backup, migration, restore and rollback have not been rehearsed for this workspace.
- A deployment's signed-in users share its configured account inventory. Multi-customer isolation and production identity lifecycle need independent review.
- AI output can be incomplete and can transmit selected scan context to an external provider.

## Historical records

Older scan metrics, earlier audits and prior release statements describe earlier code and evidence. They must not be reused as current validation. The historical incident in [copilot-authentication-fix.md](docs/copilot-authentication-fix.md) is informational only.
