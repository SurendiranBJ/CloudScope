# CloudScope — Explain with AI Authentication Failure Fix

## Summary & Incident Overview
During usage of the **Explain with AI** button on the Attack Paths page (`POST /api/v1/copilot`), users encountered the following failure banner:

- **Error**: `System Error: Session expired or unauthenticated.`
- **Request ID**: `7d025f59-4d95-4407-8e78-08cfecfd726f`

---

## 1. Confirmed Root Cause Analysis

### A. Permanent Session Lock via Stale LocalStorage Token
1. When a client had an expired, invalid, or obsolete token stored in `localStorage` under `cloudscope_token`, the frontend request interceptor in `frontend/src/api/client.ts` unconditionally injected:
   ```http
   Authorization: Bearer <stale_token>
   ```
2. The backend cryptographically verified this token against `JWT_SECRET` / `OIDC_ISSUER_URL` / `OIDC_AUDIENCE`. Because the token was stale or had an expired signature, verification failed with `401 Unauthorized` (`"Invalid authentication token"`).
3. In `frontend/src/api/client.ts`, the response interceptor received the 401 error, but **never evicted** the invalid token from `localStorage`.
4. In `frontend/src/context/AuthContext.tsx`, `isDevMode` is calculated as:
   ```ts
   const isDevMode = import.meta.env.DEV && !token;
   ```
   Because `token` remained present in React state and local storage, `isDevMode` remained `false`, effective user roles remained `[]`, and the developer role switcher in the navbar was disabled.
5. Every subsequent user interaction or click of "Explain with AI" continued to send the exact same stale token, permanently locking the developer into a 401 loop with no automated recovery path.

### B. Misleading Error Presentation as "System Error" and "AI Provider Error"
1. In `frontend/src/components/SecurityNoticeBanner.tsx`, the component handled `RATE_LIMIT` and `FORBIDDEN`, but lacked a branch for `AUTH_ERROR`. It fell through to the default block which prepended `<span className="font-semibold text-red-300">System Error:</span>`, falsely presenting a 401 authentication expiration as an internal server crash.
2. In `frontend/src/pages/AttackPaths.tsx`, `handleExplainAI` caught the 401 error and unconditionally prepended `AI Explanation Unavailable: ${detail}`, obscuring the authentication nature of the failure and making it appear as if the upstream Gemini AI model had failed.

### C. Mismatched Development Mode Headers and Backend Configuration
1. Frontend `client.ts` previously defaulted the dev role to `VIEWER` when unconfigured. Because Copilot endpoints require `Role.ANALYST` or higher, unconfigured local sessions encountered `403 Forbidden`.
2. Frontend sent `X-Dev-User` while backend `dependencies.py` expected `X-Dev-Subject`.
3. In `backend/app/security/auth.py`, asymmetric JWKS verification referenced undeclared global variables `OIDC_AUDIENCE` and `OIDC_ISSUER_URL` instead of `settings.OIDC_AUDIENCE` and `settings.OIDC_ISSUER_URL`.
4. Backend `get_current_user` in `backend/app/security/dependencies.py` needed consistent handling between bearer credentials, development header bypass (`X-Dev-Role`), and strict production fail-closed semantics.

---

## 2. Changed Files

| File | Changes Made |
|------|--------------|
| [backend/app/security/auth.py](file:///c:/Users/surab/Desktop/CloudScope/backend/app/security/auth.py) | Fixed JWKS verification to reference `settings.OIDC_AUDIENCE` and `settings.OIDC_ISSUER_URL.rstrip("/")`. |
| [backend/app/security/dependencies.py](file:///c:/Users/surab/Desktop/CloudScope/backend/app/security/dependencies.py) | Hardened `get_current_user`: Bearer tokens are cryptographically verified first (rejecting bad tokens with 401). Dev mode bypass (`X-Dev-Role`) supports both `X-Dev-Subject` and `X-Dev-User` in non-production only. Enforced fail-closed behavior in production (no unauthenticated administrator fallback, no header bypass). |
| [backend/app/security/config_validator.py](file:///c:/Users/surab/Desktop/CloudScope/backend/app/security/config_validator.py) | Standardized settings boolean reads and string stripping. |
| [backend/app/services/scanner/snapshot_store.py](file:///c:/Users/surab/Desktop/CloudScope/backend/app/services/scanner/snapshot_store.py) | Replaced scattered `os.getenv("ENVIRONMENT")` with centralized `settings.is_production`. |
| [.env](file:///c:/Users/surab/Desktop/CloudScope/.env) | Added `DEV_AUTH_MODE=true` for explicit local development mode. |
| [frontend/src/api/client.ts](file:///c:/Users/surab/Desktop/CloudScope/frontend/src/api/client.ts) | Evicts stale `cloudscope_token` from `localStorage` on 401. Attaches `X-Dev-Role`, `X-Dev-Subject`, and `X-Dev-User` in dev mode. Uses actual backend error message in `cloudscope:auth_error` event. |
| [frontend/src/context/AuthContext.tsx](file:///c:/Users/surab/Desktop/CloudScope/frontend/src/context/AuthContext.tsx) | On `cloudscope:auth_error`, resets `token` to `null` and clears `localStorage`. Restores `isDevMode` immediately in local development. Defaults `activeDevRole` to `ADMINISTRATOR` for unblocked local development out-of-the-box. |
| [frontend/src/components/SecurityNoticeBanner.tsx](file:///c:/Users/surab/Desktop/CloudScope/frontend/src/components/SecurityNoticeBanner.tsx) | Added explicit `AUTH_ERROR` banner styling (`Authentication Required (401):`) with key icon and Request ID copy utility, eliminating false "System Error:" labels. |
| [frontend/src/pages/AttackPaths.tsx](file:///c:/Users/surab/Desktop/CloudScope/frontend/src/pages/AttackPaths.tsx) | Improved `handleExplainAI` catch block: distinguishes 401 authentication errors, 403 authorization errors, 429 rate limits, and AI provider errors. Always resets loading state and retains Request ID in diagnostics. |
| [frontend/tests/authInterceptor.test.mjs](file:///c:/Users/surab/Desktop/CloudScope/frontend/tests/authInterceptor.test.mjs) | Added unit tests verifying stale token eviction from `localStorage` on 401 and `cloudscope:auth_error` event dispatching. |
| [backend/tests/test_copilot_auth_regression.py](file:///c:/Users/surab/Desktop/CloudScope/backend/tests/test_copilot_auth_regression.py) | Added 12 regression tests verifying Copilot authentication, RBAC role hierarchy, production fail-closed security, error differentiation, and secret non-disclosure. |

---

## 3. Verification & Test Results

### Backend Test Suites (`pytest`)
All 48 tests across all relevant test suites passed cleanly:
```bash
python -m pytest tests/test_phase2_authentication_rbac.py tests/test_copilot.py tests/test_config_validator.py tests/test_config_acceptance.py tests/test_copilot_auth_regression.py
```
- `tests/test_phase2_authentication_rbac.py`: 17 passed
- `tests/test_copilot.py`: 11 passed
- `tests/test_config_validator.py`: 7 passed
- `tests/test_config_acceptance.py`: 1 passed
- `tests/test_copilot_auth_regression.py`: 12 passed
- **Total**: **48 passed**, 0 failed.

### Frontend Test Suites (`node --test`)
All 22 unit tests passed:
```bash
npm test
```
- `authInterceptor injects bearer token from localStorage`: PASS
- `authInterceptor does not inject token if missing`: PASS
- `authInterceptor evicts stale token from localStorage on 401 response and dispatches auth_error`: PASS
- All graph, policy, snapshot, and regression tests: PASS
- **Total**: **22 passed**, 0 failed.

### Frontend Lint and Build
- `npm run lint`: **0 errors**.
- `npm run build`: **0 errors** (built production bundle in 1.86s).

---

## 4. Production Security Invariants Maintained

Production security is strictly fail-closed:
1. **Mandatory Authentication**: Unauthenticated requests in production return `HTTP 401 Unauthorized`.
2. **Cryptographic Verification**: Bearer tokens are cryptographically validated against configured OIDC JWKS or symmetric secret. Invalid or expired tokens are rejected with 401.
3. **No Header Bypass**: `X-Dev-Role` and `X-Dev-Subject` headers are ignored when `ENVIRONMENT=production`.
4. **No Anonymous Admin**: The anonymous fallback principal is completely disabled in production.
5. **RBAC Enforcement**: Calling `/api/v1/copilot` requires `Role.ANALYST` or higher; `Role.VIEWER` receives `HTTP 403 Forbidden`.
6. **Information Disclosure Prevention**: Tokens, API keys, and internal secrets are never reflected in error responses or logs.

---

## 5. Remaining Limitations

1. **Standalone Production Login UI**: CloudScope does not currently bundle a standalone interactive login / username-password form. In production deployments, authentication is delegated to an external enterprise OIDC / OAuth2 Identity Provider (e.g. Okta, Keycloak, AWS Cognito). The client application expects the IdP token to be supplied via standard OIDC Bearer flows.
2. **Local AI Mocking**: Testing AI Copilot endpoints in automated environments uses mocked provider responses (`CopilotAIResponse`) to prevent reliance on live Gemini network connections or consuming API quota.
