"""
CloudScope RBAC Permissions Registry.

Maps operations to required permissions and validates principal capabilities.
"""

from typing import Set
from app.security.models import Role, AuthenticatedUser, ROLE_PERMISSIONS


def get_permissions_for_roles(roles: Set[Role]) -> Set[str]:
    """Aggregate all permissions granted by a set of roles."""
    perms = set()
    for role in roles:
        perms.update(ROLE_PERMISSIONS.get(role, set()))
    return perms


def check_user_permission(user: AuthenticatedUser, required_permission: str) -> bool:
    """Validate if user holds required permission directly or via role inheritance."""
    return user.has_permission(required_permission)
