from app.config import settings
"""
CloudScope OIDC / OAuth2 JWT Authentication Service.

Validates incoming bearer tokens against OIDC issuer/JWKS endpoints or configured JWT secrets.
Ensures DEV_AUTH_MODE is explicit, never silently bypassed in production, and properly warned.
"""

import json
import logging
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional
import jwt
from jwt import PyJWKClient, PyJWTError
from fastapi import HTTPException, status

from app.security.models import AuthenticatedUser, Role

logger = logging.getLogger("cloudscope.security")



if settings.DEV_AUTH_MODE:
    logger.warning(
        "\n"
        "********************************************************************************\n"
        " [SECURITY WARNING] DEV_AUTH_MODE IS EXPLICITLY ENABLED.\n"
        " MOCK AND DEV HEADERS WILL BE ACCEPTED WITHOUT OIDC SIGNATURE VERIFICATION.\n"
        " THIS MUST NEVER BE ENABLED IN PRODUCTION DEPLOYMENTS!\n"
        "********************************************************************************\n"
    )

_jwks_client: Optional[PyJWKClient] = None
if settings.OIDC_JWKS_URL:
    try:
        _jwks_client = PyJWKClient(settings.OIDC_JWKS_URL, cache_keys=True, max_cached_keys=16, cache_jwk_set=True, lifespan=3600)
    except Exception as e:
        logger.error(f"Failed to initialize PyJWKClient for {settings.OIDC_JWKS_URL}: {e}")


def _normalize_roles(raw_roles: Any) -> List[Role]:
    """Parse role claim into recognized Role enums, defaulting to VIEWER."""
    if isinstance(raw_roles, str):
        roles_list = [raw_roles]
    elif isinstance(raw_roles, list):
        roles_list = raw_roles
    else:
        return [Role.VIEWER]

    parsed: List[Role] = []
    for r in roles_list:
        if isinstance(r, str):
            clean = r.strip().upper()
            try:
                parsed.append(Role(clean))
            except ValueError:
                # Accept only explicit role names (including namespaced role
                # claims), never substring-match arbitrary group names.
                normalized = clean.rsplit("/", 1)[-1].rsplit(":", 1)[-1].replace(" ", "_")
                if normalized in {"ADMIN", "ADMINISTRATOR"}:
                    parsed.append(Role.ADMINISTRATOR)
                elif normalized in {"SECURITY_OFFICER", "SECURITYOFFICER"}:
                    parsed.append(Role.SECURITY_OFFICER)
                elif normalized == "ANALYST":
                    parsed.append(Role.ANALYST)
                else:
                    parsed.append(Role.VIEWER)

    return parsed if parsed else [Role.VIEWER]


def _normalize_scopes(raw_scopes: Any) -> List[str]:
    """Extract scopes from token claims."""
    if isinstance(raw_scopes, str):
        return [s.strip() for s in raw_scopes.split() if s.strip()]
    elif isinstance(raw_scopes, list):
        return [str(s).strip() for s in raw_scopes if str(s).strip()]
    return []


def decode_and_verify_token(token: str) -> Dict[str, Any]:
    """Cryptographically verify JWT token signature, issuer, audience, and expiry."""
    options = {
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "require": ["exp", "sub"],
    }

    # 1. Asymmetric OIDC JWKS Verification
    if _jwks_client:
        try:
            signing_key = _jwks_client.get_signing_key_from_jwt(token)
            decode_kwargs: Dict[str, Any] = {
                "key": signing_key.key,
                "algorithms": ["RS256", "ES256", "RS384", "RS512"],
                "options": options,
            }
            if settings.OIDC_AUDIENCE:
                decode_kwargs["audience"] = settings.OIDC_AUDIENCE
            if settings.OIDC_ISSUER_URL:
                decode_kwargs["issuer"] = settings.OIDC_ISSUER_URL.rstrip("/")

            return jwt.decode(token, **decode_kwargs)
        except PyJWTError as e:
            logger.warning(f"OIDC JWKS token verification failed: {e}")
            raise ValueError(f"Invalid authentication token: {e}")

    # 2. Symmetric Secret Verification (Development / Test)
    active_secret = settings.JWT_SECRET
    if active_secret:
        try:
            active_algo = settings.JWT_ALGORITHM
            active_aud = settings.OIDC_AUDIENCE
            active_iss = settings.OIDC_ISSUER_URL.rstrip("/") if settings.OIDC_ISSUER_URL else ""

            decode_kwargs = {
                "key": active_secret,
                "algorithms": [active_algo],
                "options": options,
            }
            if active_aud:
                decode_kwargs["audience"] = active_aud
            if active_iss:
                decode_kwargs["issuer"] = active_iss

            return jwt.decode(token, **decode_kwargs)
        except PyJWTError as e:
            logger.warning(f"JWT secret token verification failed: {e}")
            raise ValueError(f"Invalid authentication token: {e}")

    # 3. Development Insecure Fallback (ONLY if DEV_AUTH_MODE explicitly enabled and NOT production)
    is_prod = settings.is_production
    if settings.DEV_AUTH_MODE and not is_prod:
        try:
            payload = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            return payload
        except Exception:
            pass

    raise ValueError("Authentication system not properly configured with OIDC JWKS or secret")


def build_principal_from_claims(claims: Dict[str, Any]) -> AuthenticatedUser:
    """Construct canonical AuthenticatedUser domain entity from verified JWT claims."""
    subject = claims.get("sub")
    if not subject:
        raise ValueError("Token missing mandatory 'sub' subject claim")

    # Extract roles from standard claim locations: roles, role, groups, realm_access
    raw_roles = (
        claims.get("roles")
        or claims.get("role")
        or claims.get("groups")
        or (claims.get("realm_access", {}).get("roles") if isinstance(claims.get("realm_access"), dict) else None)
    )

    roles = _normalize_roles(raw_roles)
    scopes = _normalize_scopes(claims.get("scope") or claims.get("scp") or claims.get("scopes"))

    return AuthenticatedUser(
        subject=str(subject),
        email=claims.get("email"),
        name=claims.get("name") or claims.get("preferred_username"),
        roles=roles,
        scopes=scopes,
        issuer=claims.get("iss", "cloudscope"),
    )
