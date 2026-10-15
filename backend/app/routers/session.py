"""Authenticated session introspection for the frontend."""

from fastapi import APIRouter, Depends

from app.security.dependencies import get_current_user
from app.security.models import AuthenticatedUser, ROLE_LEVELS, ROLE_PERMISSIONS
from app.schemas import APIResponse

router = APIRouter(tags=["Authentication"])


@router.get("/auth/me", response_model=APIResponse[dict])
def get_session_profile(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Return identity and effective roles only after backend token validation."""
    highest_level = ROLE_LEVELS.get(current_user.highest_role, 0)
    permissions = {
        permission
        for role, level in ROLE_LEVELS.items()
        if level <= highest_level
        for permission in ROLE_PERMISSIONS.get(role, set())
    }
    permissions.update(current_user.scopes)
    return APIResponse(
        success=True,
        message="Authenticated session profile retrieved successfully",
        data={
            "subject": current_user.subject,
            "email": current_user.email,
            "name": current_user.name,
            "roles": [role.value for role in current_user.roles],
            "permissions": sorted(permissions),
            "issuer": current_user.issuer,
        },
    )
