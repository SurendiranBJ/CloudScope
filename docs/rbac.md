# CloudScope Role-Based Access Control (RBAC)

## 1. Role Hierarchy
CloudScope defines 4 strict enterprise roles with monotonic privilege escalation:

| Role | Level | Primary Persona | Purpose |
| :--- | :---: | :--- | :--- |
| `VIEWER` | 1 | Auditor / Read-Only Consumer | Read-only visibility into dashboards, inventory, graphs, attack paths, alerts, and policies. |
| `ANALYST` | 2 | Security Analyst / Investigator | All VIEWER privileges plus interactive policy what-if simulations and Copilot AI natural language queries. |
| `SECURITY_OFFICER` | 3 | SecOps Lead / Compliance Officer | All ANALYST privileges plus finding triage mutations (Acknowledge, Suppress, Resolve) and viewing the audit log. |
| `ADMINISTRATOR` | 4 | Platform Owner / DevSecOps Admin | Unrestricted operational control: scanner triggers, scan-region configuration, distributed lock inspection, operational health. |

## 2. Permissions Matrix

| Permission | Description | VIEWER | ANALYST | SECURITY_OFFICER | ADMINISTRATOR |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `view:read` | Read graphs, resources, findings, risks, and alerts | ✓ | ✓ | ✓ | ✓ |
| `simulation:execute` | Run non-destructive what-if policy simulations | — | ✓ | ✓ | ✓ |
| `copilot:query` | Issue natural language analysis queries to AI Copilot | — | ✓ | ✓ | ✓ |
| `finding:mutate` | Acknowledge, suppress, or resolve security findings | — | — | ✓ | ✓ |
| `audit:view` | View administrative audit logs | — | — | ✓ | ✓ |
| `scan:trigger` | Trigger manual or scheduled AWS environment scans | — | — | — | ✓ |
| `settings:modify` | Change scan mode, regions, and collector rules | — | — | — | ✓ |
| `operations:manage` | Access system operations overview and distributed lock state | — | — | — | ✓ |

## 3. Backend Enforcement
Enforced via FastAPI dependency injection:
- `require_viewer`: Ensures principal has at least `VIEWER` role.
- `require_analyst`: Ensures principal has at least `ANALYST` role.
- `require_security_officer`: Ensures principal has at least `SECURITY_OFFICER` role.
- `require_admin`: Ensures principal has `ADMINISTRATOR` role.

Unauthorized requests immediately return HTTP 403 Forbidden with structured JSON error details:
```json
{
  "success": false,
  "detail": "Insufficient permissions. Required role: ADMINISTRATOR. Current role: VIEWER",
  "error": {
    "code": "FORBIDDEN",
    "message": "Insufficient permissions. Required role: ADMINISTRATOR. Current role: VIEWER",
    "request_id": "req-1727601234-abcd"
  },
  "request_id": "req-1727601234-abcd"
}
```

## 4. Frontend Route & Component Protection
- Routes are protected via `<ProtectedRoute minRole="ROLE">`.
- Attempted access to restricted routes renders `<Forbidden />` with explicit explanation of the required role.
- In development mode, the Navbar profile dropdown includes a dynamic **Dev Role Switcher** allowing instant switching between all 4 roles to test access boundaries.
