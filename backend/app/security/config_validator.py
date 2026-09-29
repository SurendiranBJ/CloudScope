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


def is_production() -> bool:
    """Return True if running in production environment."""
    return os.getenv("ENVIRONMENT", "development").lower() == "production"


def validate_configuration() -> Tuple[bool, List[str]]:
    """
    Validate environment configuration against security invariants.
    Returns: (is_valid: bool, issues: List[str])
    """
    issues: List[str] = []
    prod = is_production()

    auth_enabled_str = os.getenv("AUTH_ENABLED", "false").lower()
    auth_required_str = os.getenv("AUTH_REQUIRED", "false").lower()
    dev_auth_str = os.getenv("DEV_AUTH_MODE", "false").lower()

    auth_enabled = auth_enabled_str in ("true", "1", "yes")
    auth_required = auth_required_str in ("true", "1", "yes")
    dev_auth_mode = dev_auth_str in ("true", "1", "yes")

    jwt_secret = os.getenv("JWT_SECRET", "").strip()
    jwks_url = os.getenv("OIDC_JWKS_URL", "").strip()
    neo4j_pwd = os.getenv("NEO4J_PASSWORD", "").strip()

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
            elif jwt_secret.lower() in KNOWN_INSECURE_SECRETS:
                issues.append("Insecure placeholder JWT_SECRET detected in production")

        # Production invariant 4: No default database passwords
        if neo4j_pwd.lower() in KNOWN_INSECURE_SECRETS:
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

