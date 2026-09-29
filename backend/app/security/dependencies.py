"""
CloudScope FastAPI Authentication & RBAC Dependencies.

Provides dependency injection for endpoint authentication and declarative role enforcement.
"""

import os
from typing import Callable, Optional
from fastapi import Depends, HTTPException, Header, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.security.auth import (
    AUTH_REQUIRED,
    DEV_AUTH_MODE,
    build_principal_from_claims,
    decode_and_verify_token,
)
from app.security.models import AuthenticatedUser, Role

security_scheme = HTTPBearer(auto_error=False)


def is_auth_required() -> bool:
    """Authentication is unconditionally mandatory in production."""
    if os.getenv("ENVIRONMENT", "development").lower() == "production":
        return True
    if os.getenv("AUTH_REQUIRED", "false").lower() in ("true", "1", "yes"):
        return True
    return bool(globals().get("AUTH_REQUIRED", False))


def is_dev_auth_mode() -> bool:
    """DEV_AUTH_MODE is unconditionally forbidden in production."""
    if os.getenv("ENVIRONMENT", "development").lower() == "production":
        return False
    if os.getenv("DEV_AUTH_MODE", "false").lower() in ("true", "1", "yes"):
        return True
    return bool(globals().get("DEV_AUTH_MODE", False))


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    x_dev_role: Optional[str] = Header(None, alias="X-Dev-Role"),
    x_dev_subject: Optional[str] = Header(None, alias="X-Dev-Subject"),
) -> AuthenticatedUser:
    """Resolve and authenticate the calling principal."""
    prod = os.getenv("ENVIRONMENT", "development").lower() == "production"
    dev_mode = is_dev_auth_mode()
    auth_req = is_auth_required()

    # 1. Explicit Development Auth Bypass (Dev mode only - prohibited in production)
    if dev_mode and not prod:
        if x_dev_role:
            try:
                role = Role(x_dev_role.strip().upper())
            except ValueError:
                role = Role.ADMINISTRATOR
            sub = x_dev_subject.strip() if x_dev_subject else "dev-user"
            return AuthenticatedUser(
                subject=sub,
                email=f"{sub}@cloudscope.dev",
                name="Developer User",
                roles=[role],
                scopes=["*"],
                issuer="cloudscope:dev",
            )

        # In dev mode, if no bearer token is supplied and auth is not strictly required, provide dev admin
        if not credentials and not auth_req:
            return AuthenticatedUser(
                subject="local-dev-admin",
                email="admin@cloudscope.dev",
                name="Local Dev Admin",
                roles=[Role.ADMINISTRATOR],
                scopes=["*"],
                issuer="cloudscope:dev",
            )

    # 2. Bearer Token Verification
    if credentials and credentials.credentials:
        token = credentials.credentials.strip()
        claims = decode_and_verify_token(token)
        return build_principal_from_claims(claims)

    # 3. If Authentication is Required (mandatory in production), reject unauthenticated requests
    if auth_req or prod:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Backward-compatible default for unauthenticated local development / test suites
    return AuthenticatedUser(
        subject="default-admin",
        email="default-admin@cloudscope.local",
        name="Default Administrator",
        roles=[Role.ADMINISTRATOR],
        scopes=["*"],
        issuer="cloudscope:local",
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
