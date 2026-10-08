# CloudScope Security Release Checklist

## 1. Authentication
- [x] **PASS**: missing bearer token rejected when required
- [x] **PASS**: invalid token rejected
- [x] **PASS**: expired token rejected
- [x] **PASS**: invalid signature rejected
- [x] **PASS**: issuer validated
- [x] **PASS**: audience validated
- [x] **PASS**: JWKS HTTPS enforced when used
- [x] **PASS**: DEV_AUTH_MODE cannot operate in production

## 2. RBAC (Role-Based Access Control)
### Server-side Authorization
- [x] **PASS**: VIEWER role enforcement verified
- [x] **PASS**: ANALYST role enforcement verified
- [x] **PASS**: SECURITY_OFFICER role enforcement verified
- [x] **PASS**: ADMINISTRATOR role enforcement verified
- [x] **PASS**: Frontend visibility is NOT a security boundary (all boundaries enforced server-side)

### Protected Operations
- [x] **PASS**: scan trigger (unauthorized triggers removed from all routers, admin-only allowed)
- [x] **PASS**: graph rebuild
- [x] **PASS**: simulation
- [x] **PASS**: findings mutation
- [x] **PASS**: alert mutation
- [x] **PASS**: audit access
- [x] **PASS**: reports
- [x] **PASS**: operational endpoints

## 3. Scanner Coordination & Lock
- [x] **PASS**: Redis distributed lock
- [x] **PASS**: owner token
- [x] **PASS**: lease expiration
- [x] **PASS**: heartbeat
- [x] **PASS**: owner-only release
- [x] **PASS**: fail-closed Redis failure
- [x] **PASS**: Two backend workers must never legitimately publish the same scan simultaneously
- [x] **PASS**: SQL authoritative state must be durable before the new snapshot becomes current
- [x] **PASS**: Failed persistence must not result in "published successfully" (atomic check in SnapshotStore)
- [x] **PASS**: Redis must not be the only durable snapshot source
- [x] **PASS**: Restart recovery

## 4. API Security
- [x] **PASS**: CORS configuration hardened
- [x] **PASS**: Security headers implemented
- [x] **PASS**: Rate limiting active on critical endpoints
- [x] **PASS**: Request IDs for tracing and audit
- [x] **PASS**: Error responses sanitized (no stack traces or internal exception details)
- [x] **PASS**: Metrics access restricted/protected
- [x] **PASS**: Health endpoints properly scoped
- [x] **PASS**: Information leakage prevented
- [x] **PASS**: Debug output disabled in production
- [x] **PASS**: No exposed secrets (AWS credentials, JWT secrets, Gemini keys, database passwords)

## 5. Docker Security
- [x] **PASS**: Containers run as non-root users (`cloudscope` in backend, `nginx` in frontend via `nginxinc/nginx-unprivileged:alpine`)
- [x] **PASS**: No insecure default passwords
- [x] **PASS**: No unnecessary public ports
- [x] **PASS**: Internal infrastructure isolated (Neo4j and Redis on `cloudscope-internal` network)
- [x] **PASS**: Health checks configured for all containers
- [x] **PASS**: Restart policies implemented (`unless-stopped`)
- [x] **PASS**: Read-only AWS credential mount in local profile mode (`:ro`)

## 6. CI/CD Security (GitHub Actions)
- [x] **PASS**: Excessive permissions removed (`permissions: contents: read` enforced globally)
- [x] **PASS**: Secret exposure mitigated
- [x] **PASS**: Dependency audit included (`npm audit --audit-level=high`)
- [x] **PASS**: Secret scanning enabled
- [x] **PASS**: Unsafe shell interpolation checked
- [x] **PASS**: Unnecessary token permissions removed

All P0/P1 issues are resolved and verified. Production configuration is internally safe.
