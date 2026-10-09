"""CloudScope Security & Authentication Package."""

from app.security.models import Role, AuthenticatedUser, ROLE_LEVELS, ROLE_PERMISSIONS
from app.security.auth import (
    decode_and_verify_token,
    build_principal_from_claims,
)
from app.security.dependencies import (
    get_current_user,
    require_role,
    require_viewer,
    require_analyst,
    require_security_officer,
    require_admin,
)

__all__ = [
    "Role",
    "AuthenticatedUser",
    "ROLE_LEVELS",
    "ROLE_PERMISSIONS",
    "decode_and_verify_token",
    "build_principal_from_claims",
    "get_current_user",
    "require_role",
    "require_viewer",
    "require_analyst",
    "require_security_officer",
    "require_admin",
]
