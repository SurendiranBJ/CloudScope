# Authentication

CloudScope accepts bearer JWTs when authentication is required. The backend verifies the token signature and configured issuer/audience; asymmetric keys can be resolved through `OIDC_JWKS_URL`. See [configuration reference](configuration-reference.md).

## Local development

For an isolated workstation only, `DEV_AUTH_MODE=true` enables development identity headers: `X-Dev-Role` and `X-Dev-Subject`. `X-Dev-User` is accepted as a compatibility alias for the development subject. In a non-production environment with auth not required, the backend can also provide an anonymous development principal. Do not expose these modes to an untrusted network.

Production startup validation rejects development authentication and requires authentication/OIDC configuration. Do not infer that local successful access proves a production IdP login works.

## Production responsibilities

CloudScope does not provide an identity-provider onboarding system. The operator configures token issuance, issuer/audience, signing keys, role claims, MFA, session expiry, recovery, and account lifecycle. Map claims to `VIEWER`, `ANALYST`, `SECURITY_OFFICER`, or `ADMINISTRATOR` and test every sensitive route.

The backend is the authorization boundary. Hiding a button or page in React is not access control. Different APIs use different minimum roles; see [RBAC](rbac.md) and the deployed OpenAPI schema.

## Account and user-data scope

AWS account selection is deployment-level: the backend's configured AWS credentials choose the one account scanned by that deployment. Signed-in users generally share the deployment's AWS inventory and snapshots. Some user workflows such as simulation drafts are scoped to the authenticated analyst. The application does not currently expose Projects or self-service account registration. Multi-customer isolation requires separate reviewed deployment boundaries.
