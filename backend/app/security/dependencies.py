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
    """Auth is required by default, unless explicitly bypassed in dev mode."""
    if settings.is_production:
        return True
    # If in dev, auth is required unless DEV_AUTH_MODE is explicitly True
    if settings.DEV_AUTH_MODE:
        return False
    return True

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

    # 1. Explicit Development Auth Bypass (Dev mode only - prohibited in production)
    if dev_mode and not prod:
        if x_dev_role:
            try:
                role = Role(x_dev_role.strip().upper())
            except ValueError:
                role = Role.VIEWER
            sub = x_dev_subject.strip() if x_dev_subject else "dev-user"
            return AuthenticatedUser(
                subject=sub,
                email=f"{sub}@cloudscope.dev",
                name="Developer User",
                roles=[role],
                scopes=["*"],
                issuer="cloudscope:dev",
            )

    # 2. Bearer Token Verification
    if credentials and credentials.credentials:
        token = credentials.credentials.strip()
        try:
            claims = decode_and_verify_token(token)
            return build_principal_from_claims(claims)
        except ValueError as e:
            # Catch token validation errors and return generic 401 to avoid info disclosure
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 3. Reject unauthenticated requests
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
