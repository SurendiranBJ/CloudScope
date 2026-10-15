# Secret Management and Data Handling

## AWS access

CloudScope application collection is designed to use AWS read APIs. Configure the AWS principal as read-only; code-level intent is not an IAM boundary. For cross-account projects, use a dedicated role with a restrictive trust policy and the generated per-project ExternalId. Avoid long-lived access keys where workload roles or short-lived profiles are available. Never commit AWS credentials.

## What-if simulation

Simulation drafts are persisted in relational storage and scoped by authenticated issuer, subject, and selected project. They are application-side what-if changes only. They are not executed against AWS and do not update the AWS graph. Protect the database and its backups because drafts can reveal intended permission changes.

## AI provider data

AI explanations send selected cloud inventory/finding/attack-path context to the configured Gemini provider. Do not enable the feature for sensitive customer data until the organization has approved provider terms, retention, residency, consent, and data-minimization behavior. The AI response is advisory and must be checked against source evidence.

## Credential and secret redaction

The sanitizer attempts to detect common AWS access keys, tokens, Gemini keys, private keys, and sensitive dictionary fields before logging or AI dispatch. Redaction is defense in depth, not a guarantee that every possible secret format is caught. Do not store secret values in resource tags, policy descriptions, logs, or finding notes.

## Operational handling

- Inject secrets from a managed secret store for deployed environments.
- Keep .env files local and excluded from Git.
- Rotate credentials if they may have appeared in logs or working copies.
- Restrict access to SQL snapshots, audit records, project ExternalIds, Redis, Neo4j, and backups.
- Verify actual IAM permissions and network access independently of CloudScope.
