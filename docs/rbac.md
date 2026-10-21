# Roles and access control

CloudScope defines four ordered roles. A higher role inherits checks that require a lower minimum role, but endpoint coverage is route-specific; this is not a fine-grained permission matrix.

| Role | Typical use | Current access summary |
| --- | --- | --- |
| `VIEWER` | Read-only review | Read dashboard, resources, policies, graph, attack paths, findings, alerts, and reports. |
| `ANALYST` | Investigation | Viewer access plus simulations and AI Copilot endpoints. |
| `SECURITY_OFFICER` | Finding workflow | Analyst access plus finding state changes, audit log, and report export where routed. |
| `ADMINISTRATOR` | Application administration | Security-officer access plus scan triggers, settings, health diagnostics, and operations. |

The backend is authoritative: API routers use role dependencies and return 401 when identity is required but absent/invalid, or 403 when the principal lacks the minimum role. Some feature pages may be visible in the frontend even when the API denies access; UI visibility alone does not grant permission. Authentication claims and the external identity provider must be configured by the operator (see [authentication.md](authentication.md)).

## AWS account scope

AWS identity is configured on the backend, and all signed-in users of a deployment view analysis for that configured account. CloudScope no longer provides per-user account projects or target-role onboarding. Use separate deployments with independently configured credentials to analyze separate accounts.

## Local development

The development role headers are a local testing convenience only. They are not a production identity mechanism. Production configuration must disable `DEV_AUTH_MODE` and require valid JWT/OIDC verification.
