"""
CloudScope Authenticated Principal & RBAC Domain Models.

Defines roles, role hierarchies, permissions, and the canonical AuthenticatedUser domain entity.
"""

from enum import Enum
from typing import List, Optional, Set
from pydantic import BaseModel, Field


class Role(str, Enum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    ADMINISTRATOR = "ADMINISTRATOR"


ROLE_LEVELS = {
    Role.VIEWER: 1,
    Role.ANALYST: 2,
    Role.SECURITY_OFFICER: 3,
    Role.ADMINISTRATOR: 4,
}


ROLE_PERMISSIONS: dict[Role, Set[str]] = {
    Role.VIEWER: {
        "dashboard:read",
        "resources:read",
        "policies:read",
        "relationships:read",
        "graph:read",
        "attack_paths:read",
        "risk:read",
        "alerts:read",
        "reports:read",
        "findings:read",
    },
    Role.ANALYST: {
        "simulation:execute",
        "copilot:chat",
        "findings:evidence:read",
    },
    Role.SECURITY_OFFICER: {
        "findings:acknowledge",
        "findings:resolve",
        "findings:suppress",
        "findings:reopen",
        "reports:export",
    },
    Role.ADMINISTRATOR: {
        "scan:trigger",
        "scan:configure_interval",
        "scan:configure_region",
        "audit:read",
        "operations:read",
        "settings:manage",
    },
}


class AuthenticatedUser(BaseModel):
    """Canonical representation of an authenticated principal."""

    subject: str = Field(..., description="Stable JWT subject identifier (never email)")
    email: Optional[str] = None
    name: Optional[str] = None
    roles: List[Role] = Field(default_factory=lambda: [Role.VIEWER])
    scopes: List[str] = Field(default_factory=list)
    issuer: str = "cloudscope"

    def max_role(self) -> Role:
        """Return the highest privilege role held by this user."""
        if not self.roles:
            return Role.VIEWER
        return max(self.roles, key=lambda r: ROLE_LEVELS.get(r, 0))

    @property
    def highest_role(self) -> Role:
        """Property alias returning the highest privilege role held by this user."""
        return self.max_role()

    def has_role(self, minimum_role: Role) -> bool:
        """Check if user holds at least the minimum role level."""
        min_level = ROLE_LEVELS.get(minimum_role, 0)
        return any(ROLE_LEVELS.get(r, 0) >= min_level for r in self.roles)

    def has_permission(self, permission: str) -> bool:
        """Check if any of user's roles grant the requested permission."""
        user_max_level = ROLE_LEVELS.get(self.max_role(), 0)
        for role, level in ROLE_LEVELS.items():
            if level <= user_max_level and permission in ROLE_PERMISSIONS.get(role, set()):
                return True
        return permission in self.scopes
