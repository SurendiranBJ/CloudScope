# Authentication

CloudScope accepts bearer JWTs when authentication is required. The backend validates the signature and, when configured, the issuer and audience. OIDC settings are `OIDC_JWKS_URL`, `OIDC_ISSUER_URL`, and `OIDC_AUDIENCE`; see [configuration-reference.md](configuration-reference.md).

## Local development

For an isolated local environment only, `DEV_AUTH_MODE=true` enables development identity headers (`X-Dev-Role` and `X-Dev-Subject`; `X-Dev-User` is accepted as a compatibility alias). The Compose development configuration may also disable required authentication. This can grant broad development access, so never expose such a configuration to an untrusted network or use it in production. Production startup validation rejects development auth and requires OIDC/JWT settings.

## Production responsibilities

CloudScope does not provide a hosted identity-provider onboarding flow. Configure the IdP, token issuance, role claims, MFA, session expiry, and account lifecycle in the deployment environment. Confirm the IdP's claims map to the four supported roles: `VIEWER`, `ANALYST`, `SECURITY_OFFICER`, and `ADMINISTRATOR`. Backend dependencies enforce roles; frontend route visibility is not an authorization boundary.

Project access is additionally scoped by the authenticated principal in project endpoints. Review [rbac.md](rbac.md) and [security.md](security.md) before deployment; do not treat this prototype's application checks as a substitute for a tenant-isolation review.
