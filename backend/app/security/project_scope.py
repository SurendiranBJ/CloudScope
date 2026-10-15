"""Validate and pin the active account project for security-data requests."""

from typing import AsyncGenerator

from fastapi import Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials

from app.persistence.database import get_db_session
from app.persistence.models import CloudProjectModel
from app.security.dependencies import get_current_user
from app.config import settings
from app.services.project_context import reset_project_id, set_project_id
from app.services.scanner import current_snapshot


async def project_scope(
    request: Request,
    selected_project: str | None = Header(None, alias="X-CloudScope-Project"),
) -> AsyncGenerator[None, None]:
    """Resolve a principal-owned project and pin its snapshot for this request.

    The project registry itself remains usable before an account is selected. For
    legacy single-account installations without registered projects, global mode
    remains available. Once projects exist, data requests cannot fall back to the
    global snapshot.
    """
    if request.url.path in {"/api/v1/live", "/api/v1/ready"} or request.url.path.startswith(("/api/v1/projects", "/api/v1/session", "/api/v1/health")):
        yield
        return

    authorization = request.headers.get("authorization", "")
    scheme, _, token_value = authorization.partition(" ")
    credentials = (
        HTTPAuthorizationCredentials(scheme=scheme, credentials=token_value)
        if scheme.lower() == "bearer" and token_value
        else None
    )
    user = get_current_user(
        request,
        credentials=credentials,
        x_dev_role=request.headers.get("x-dev-role"),
        x_dev_subject=request.headers.get("x-dev-subject") or request.headers.get("x-dev-user"),
    )

    owner_issuer = user.issuer or "cloudscope"
    project = None
    resolved_id = None
    with get_db_session() as session:
        owned = session.query(CloudProjectModel).filter_by(
            owner_issuer=owner_issuer, owner_subject=user.subject, status="ACTIVE"
        )
        if selected_project:
            project = owned.filter_by(project_id=selected_project).first()
            if project is None:
                raise HTTPException(status_code=404, detail="Project not found")
        else:
            projects = owned.order_by(CloudProjectModel.created_at, CloudProjectModel.project_id).limit(2).all()
            if len(projects) == 1:
                project = projects[0]
            elif len(projects) > 1:
                raise HTTPException(status_code=409, detail="Select an AWS project before viewing account data")
            elif settings.is_production:
                raise HTTPException(status_code=409, detail="Register and select an AWS project before viewing account data")

        resolved_id = project.project_id if project else None

    token = set_project_id(resolved_id)
    snapshot_token = current_snapshot.pin_request_snapshot()
    try:
        yield
    finally:
        current_snapshot.reset_request_snapshot(snapshot_token)
        reset_project_id(token)
