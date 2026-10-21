# Roles and Access Control

CloudScope defines four ordered roles. A higher role satisfies checks for a lower minimum role, but actual route guards vary by endpoint. The table summarizes the permission registry and representative protected routes; always check the deployed OpenAPI schema and router dependency for exact behavior.

| Role | Typical use | Permission intent / representative APIs |
| --- | --- | --- |
| `VIEWER` | Review current security state | Read dashboard, resources, policies, relationships, graph, attack paths, risks, alerts, reports and findings; read scan status and snapshot history. |
| `ANALYST` | Investigate and model changes | Viewer access plus simulation actions and Copilot; read finding evidence. |
| `SECURITY_OFFICER` | Triage findings and export | Analyst access plus finding acknowledge/resolve/suppress/reopen, audit endpoints guarded by `require_security_officer`, finding triage, and report export. |
| `ADMINISTRATOR` | Operate the deployment | Security-officer access plus manual scan triggers, scan interval/region configuration, settings, AWS diagnostics and operations overview. |

Some endpoints have distinct dependencies. For example, `/health` diagnostics and `/api/v1/operations/overview` require administrator; the audit router uses the security-officer minimum. The permission registry and route guard should both be reviewed because a registry entry does not automatically protect a route unless its dependency checks it.

## Enforcement behavior

- A valid bearer JWT is resolved to an authenticated principal and role set.
- Missing/invalid authentication returns 401 when auth is required.
- A principal below a route's minimum role returns 403.
- Non-production development mode may accept `X-Dev-Role` and `X-Dev-Subject`; it is not suitable for untrusted networks.
- Production must disable development auth and configure a trusted identity provider.
- Frontend navigation/visibility is a usability feature only; server route dependencies enforce access.

## Account and data boundaries

One backend deployment scans the AWS account identified by its configured credential chain. There is no current Projects/account registration UI. AWS inventory and snapshots are shared within that deployment for authenticated users; durable simulation changes are additionally scoped to analyst identity. This is not a general multi-tenant guarantee. Use separate deployments, credentials, databases and network controls where separation is required.

Legacy `cloud_projects` tables and `project_id` columns may remain in database schema for compatibility. Their presence does not enable project selection in the current UI or scanner credential flow.

See [authentication](authentication.md), [security overview](security.md), and [release readiness](release-readiness.md).
