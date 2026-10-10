from app.config import settings
"""
CloudScope Centralized Configuration & Security Invariant Validator.

Enforces production security invariants:
1. If ENVIRONMENT=production:
   - Authentication must be enabled (AUTH_ENABLED=True)
   - Authentication must be required (AUTH_REQUIRED=True)
   - DEV_AUTH_MODE must be False
   - Valid OIDC JWKS URL or strong JWT_SECRET (>= 32 chars, not a placeholder) must be configured
   - Insecure default credentials (NEO4J_PASSWORD=password) are strictly prohibited
2. Centralized validation fails startup and readiness if production invariants are violated.
"""

import os
import logging
from typing import List, Tuple

logger = logging.getLogger("cloudscope.security.validator")

KNOWN_INSECURE_SECRETS = {
    "password",
    "secret",
    "admin",
    "changeme",
    "dev-secret-key-change-in-production-min-32-chars-long",
    "test-secret",
    "123456",
}

def is_placeholder(val: str) -> bool:
    if not val:
        return False
    v = val.lower()
    if v.startswith("replace-with"):
        return True
    if "changeme" in v:
        return True
    if "example-only" in v:
        return True
    if v in KNOWN_INSECURE_SECRETS:
        return True
    return False


def is_production() -> bool:
    """Return True if running in production environment."""
    return settings.is_production


def validate_configuration() -> Tuple[bool, List[str]]:
    """
    Validate environment configuration against security invariants.
    Returns: (is_valid: bool, issues: List[str])
    """
    issues: List[str] = []
    prod = is_production()

    auth_enabled = bool(settings.AUTH_ENABLED)
    auth_required = bool(settings.AUTH_REQUIRED)
    dev_auth_mode = bool(settings.DEV_AUTH_MODE)

    jwt_secret = (settings.JWT_SECRET or "").strip()
    jwks_url = (settings.OIDC_JWKS_URL or "").strip()
    issuer_url = (settings.OIDC_ISSUER_URL or "").strip()
    audience = (settings.OIDC_AUDIENCE or "").strip()
    neo4j_pwd = (settings.NEO4J_PASSWORD or "").strip()

    if prod:
        # Production invariant 1: DEV_AUTH_MODE is prohibited
        if dev_auth_mode:
            issues.append("DEV_AUTH_MODE=true is strictly prohibited in production")

        # Production invariant 2: Authentication must be enabled & required
        if not auth_enabled:
            issues.append("AUTH_ENABLED must be true in production")
        if not auth_required:
            issues.append("AUTH_REQUIRED must be true in production")

        # Production invariant 3: Strong cryptographic keying required
        if not jwks_url:
            if not jwt_secret:
                issues.append("Production requires OIDC_JWKS_URL or a strong JWT_SECRET")
            elif len(jwt_secret) < 32:
                issues.append("JWT_SECRET must be at least 32 characters in production")
            elif is_placeholder(jwt_secret):
                issues.append("Insecure placeholder JWT_SECRET detected in production")

        if not issuer_url:
            issues.append("OIDC_ISSUER_URL is required in production for issuer validation")
        elif is_placeholder(issuer_url):
            issues.append("Insecure placeholder OIDC_ISSUER_URL detected in production")
            
        if not audience:
            issues.append("OIDC_AUDIENCE is required in production for audience validation")
        elif is_placeholder(audience):
            issues.append("Insecure placeholder OIDC_AUDIENCE detected in production")
            
        if jwks_url and not jwks_url.lower().startswith("https://"):
            issues.append("OIDC_JWKS_URL must use HTTPS in production")

        # Production invariant 4: No default database passwords
        if is_placeholder(neo4j_pwd):
            issues.append(f"Insecure default NEO4J_PASSWORD ('{neo4j_pwd}') detected in production")

    return len(issues) == 0, issues


class ConfigurationError(RuntimeError):
    """Raised when application startup invariants are violated in production."""
    pass


def enforce_startup_configuration() -> None:
    """Validate configuration on application startup. Fails closed in production."""
    valid, issues = validate_configuration()
    if not valid:
        error_msg = (
            "CRITICAL SECURITY CONFIGURATION VIOLATION IN PRODUCTION:\n"
            + "\n".join(f"  - {issue}" for issue in issues)
        )
        logger.critical(error_msg)
        if is_production():
            raise ConfigurationError(error_msg)
    else:
        if is_production():
            logger.info("Production security configuration validated successfully.")


validate_startup_configuration = enforce_startup_configuration

