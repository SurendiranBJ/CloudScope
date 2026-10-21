# Secret Management and Data Handling

## AWS credentials

CloudScope uses the AWS credentials configured on the backend and analyzes the account returned by that identity. Prefer workload identity, federation or short-lived profiles over long-lived IAM user keys. Do not place credentials in frontend variables, source control, screenshots or issue attachments. For local Compose, the AWS credentials directory is mounted read-only; use a dedicated read-only scanner principal and verify its account with STS.

The UI does not currently register accounts or assume a user-selected role. Separate accounts require separate backend deployments and independently protected credential sources.

## What-If Analysis

Simulation changes are persisted in SQL and scoped to the authenticated analyst. They may reveal intended permission changes, identity names and policy ARNs, so protect the database, exports and backups. They are proposals only: simulation does not send IAM mutation requests to AWS or change the published live graph.

## AI provider data

When an AI explanation is requested, selected scan inventory/finding/attack-path/alert context is sent by the backend to the configured Gemini provider. Do not enable the feature for sensitive customer data until provider terms, retention, residency, consent, minimization and organizational policy have been reviewed. AI output is advisory.

## Redaction and logging

Application sanitizers try to identify common AWS keys/tokens, Gemini credentials, private keys and sensitive dictionary fields before logging or AI dispatch. This is defense in depth, not a guarantee for every possible value or encoding. Keep secret values out of resource tags, descriptions, finding notes, prompts and audit metadata.

## Operational handling

- Inject secrets from a managed secret store in deployed environments.
- Keep `.env` local and excluded from Git; replace every example value.
- Rotate any credential suspected to have appeared in logs or a working copy.
- Restrict access to SQL snapshots, Redis, Neo4j, logs, exports and backups.
- Protect user identity data and resource metadata under the organization's data retention and residency rules.
- Recheck actual AWS permissions and network controls independently of CloudScope.
