from app.config import settings
"""
CloudScope FastAPI Authentication & RBAC Dependencies.

Provides dependency injection for endpoint authentication and declarative role enforcement.
"""

import os
from typing import Callable, Optional
from fastapi import Depends, HTTPException, Header, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.security.auth import (
    build_principal_from_claims,
    decode_and_verify_token,
)
from app.security.models import AuthenticatedUser, Role

security_scheme = HTTPBearer(auto_error=False)


def is_auth_required() -> bool:
    """Auth is required by default in production or when AUTH_REQUIRED=True."""
    if settings.is_production:
        return True
    # Dev mode explicit bypass disables auth enforcement
    if settings.DEV_AUTH_MODE:
        return False
    # Respect the AUTH_REQUIRED flag (default False in dev/test environments)
    return settings.AUTH_REQUIRED

def is_dev_auth_mode() -> bool:
    """DEV_AUTH_MODE is unconditionally forbidden in production."""
    if settings.is_production:
        return False
    return settings.DEV_AUTH_MODE


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    x_dev_role: Optional[str] = Header(None, alias="X-Dev-Role"),
    x_dev_subject: Optional[str] = Header(None, alias="X-Dev-Subject"),
) -> AuthenticatedUser:
    """Resolve and authenticate the calling principal."""
    prod = settings.is_production
    dev_mode = is_dev_auth_mode()
    auth_req = is_auth_required()

    # 1. Bearer Token Verification (cryptographically verified if provided)
    if credentials and credentials.credentials:
        token = credentials.credentials.strip()
        try:
            claims = decode_and_verify_token(token)
            return build_principal_from_claims(claims)
        except ValueError:
            # Catch token validation errors and return generic 401 to avoid info disclosure
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 2. Explicit Development Auth Bypass (Dev mode only - strictly prohibited in production)
    if dev_mode and not prod:
        dev_role_hdr = x_dev_role or request.headers.get("x-dev-role")
        dev_sub_hdr = x_dev_subject or request.headers.get("x-dev-user") or request.headers.get("x-dev-subject")
        if dev_role_hdr:
            try:
                role = Role(dev_role_hdr.strip().upper())
            except ValueError:
                role = Role.VIEWER
            sub = (dev_sub_hdr or "dev-user").strip()
            return AuthenticatedUser(
                subject=sub,
                email=f"{sub}@cloudscope.dev",
                name="Developer User",
                roles=[role],
                scopes=["*"],
                issuer="cloudscope:dev",
            )

    # 3. Handle unauthenticated requests (Dev/test environment ONLY when auth is not required)
    if not prod and not auth_req:
        # Auth not required (dev/test environment) — grant anonymous admin access
        return AuthenticatedUser(
            subject="anonymous",
            email="anonymous@cloudscope.dev",
            name="Anonymous",
            roles=[Role.ADMINISTRATOR],
            scopes=["*"],
            issuer="cloudscope:dev",
        )

    # 4. Fail closed: production or auth required without valid credentials
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please provide a valid Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(minimum_role: Role) -> Callable:
    """FastAPI dependency factory enforcing a minimum RBAC role level."""

    def role_checker(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if not user.has_role(minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient privileges. Required role: '{minimum_role.value}'",
            )
        return user

    return role_checker


# Convenient pre-bound role dependencies
require_viewer = require_role(Role.VIEWER)
require_analyst = require_role(Role.ANALYST)
require_security_officer = require_role(Role.SECURITY_OFFICER)
require_admin = require_role(Role.ADMINISTRATOR)
