# CloudScope Master Security Architecture

## 1. Executive Summary
CloudScope is an enterprise-grade cloud security posture and identity analysis platform designed from the ground up for strict operational security, defense-in-depth, and compliance readiness.

## 2. Core Security Pillars

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Security Architecture                         │
├───────────────────┬───────────────────┬─────────────────────────────────┤
│   Authentication  │   Authorization   │      Operational Hardening      │
│   (OIDC / JWT)    │   (Monotonic RBAC)│  (Distributed Lock, Probes, CI) │
├───────────────────┼───────────────────┼─────────────────────────────────┤
│   Rate Limiting   │   Audit Logging   │      Secret Sanitization        │
│  (Sliding Window) │ (Tamper-Evident)  │     (Zero Leakage Guarantee)    │
└───────────────────┴───────────────────┴─────────────────────────────────┘
```

### 1. Authentication
Cryptographic verification of JWTs signed by enterprise identity providers (Keycloak, Okta, Azure AD, Auth0) or local HMAC secrets. Validates expiration, signature, issuer, and audience. Subject (`sub`) provides an immutable principal identifier.

### 2. Role-Based Access Control (RBAC)
Strict 4-tier monotonic role system:
- `VIEWER`: Read-only access to inventory, graph, attack paths, and risk assessment.
- `ANALYST`: Non-destructive what-if policy simulations and AI Copilot queries.
- `SECURITY_OFFICER`: Finding lifecycle triage (acknowledge/resolve) and audit logs.
- `ADMINISTRATOR`: Operational oversight, scan triggers, region configuration, lock management.

### 3. Rate Limiting & Throttling
Sliding window rate limiter backed by Redis with in-memory fallback:
- Bounded capacity per authenticated user ID (or IP address for public probes).
- Rejections return HTTP 429 Too Many Requests with standard `Retry-After: <seconds>` headers.

### 4. Distributed Scan Coordination & Mutual Exclusion
Distributed lock `cloudscope:scan:lock` ensures only one instance can perform an AWS scan at any given moment:
- Redis atomic `SET NX EX` with unique UUID ownership token.
- Background heartbeat lease renewal every 10 seconds.
- Lua script verification on release to prevent stale lock hijacking.
- 120-second lease TTL ensures dead instances do not hold locks forever.

### 5. Durable State & Redis Decoupling
Redis is used solely as an ephemeral cache and lock coordinator. All scan run records, snapshots, and finding states are written to a durable relational database (SQLite/PostgreSQL) ensuring zero data loss across container restarts.

### 6. Administrative Audit Trail
All administrative and operational actions (`SCAN_TRIGGERED`, `FINDING_MUTATED`, `SIMULATION_EXECUTED`, `COPILOT_REQUESTED`, `SETTINGS_UPDATED`) are durably recorded with automatic secret sanitization and a 90-day retention policy.

### 7. Centralized Sanitization & Zero AWS Write Guarantee
- Scanner IAM permissions are strictly read-only (`Get*`, `List*`, `Describe*`).
- Automated regex and key redaction prevents credentials, private keys, and API tokens from entering logs, audit records, or AI context.
