# CloudScope Authentication Architecture

## 1. Overview
CloudScope enforces enterprise-grade identity authentication via JSON Web Tokens (JWT) adhering to the OpenID Connect (OIDC) and OAuth 2.0 specifications. Every incoming API request to protected resources must provide an `Authorization: Bearer <token>` header, except for public liveness probes.

## 2. JWT Verification & Validation
Token validation is handled in `backend/app/security/auth.py` and verifies:
- **Signature Integrity**: Cryptographically validated using either symmetric HMAC secrets (`HS256`, `HS384`, `HS512`) or asymmetric RSA / ECDSA keypairs (`RS256`, `ES256`) via OIDC JSON Web Key Sets (JWKS).
- **Expiration (`exp`)**: Tokens past their expiration timestamp are rejected immediately with HTTP 401.
- **Not Before / Issued At (`nbf`, `iat`)**: Future-dated tokens are rejected with a 30-second leeway window.
- **Issuer (`iss`)**: Validated against `OIDC_ISSUER` when configured.
- **Audience (`aud`)**: Validated against `OIDC_AUDIENCE` when configured.

## 3. Principal Identity & Claims Normalization
The primary subject identifier (`sub`) is extracted as the immutable unique user identity. Roles and permissions are mapped from standard claims:
- `roles` or `realm_access.roles` (Keycloak / standard OIDC)
- `groups` (Okta / Azure AD)
- `scope` / `scp` (OAuth 2.0 scopes)

```python
# AuthenticatedUser model
@dataclass
class AuthenticatedUser:
    id: str
    email: Optional[str]
    roles: List[Role]
    permissions: Set[Permission]
    token_claims: Dict[str, Any]
```

## 4. Development Authentication Mode (`DEV_AUTH_MODE`)
For local workstation development, testing, and isolated evaluation environments:
- When `DEV_AUTH_MODE=true`, the backend accepts `X-Dev-Role` and `X-Dev-User` HTTP headers in place of a full identity provider token.
- Valid roles for `X-Dev-Role`: `VIEWER`, `ANALYST`, `SECURITY_OFFICER`, `ADMINISTRATOR`.
- Whenever `DEV_AUTH_MODE` is enabled, the backend logs prominent security warning banners on startup.
- In production (`DEV_AUTH_MODE=false`), dev headers are strictly ignored and all requests require cryptographically signed JWTs.
