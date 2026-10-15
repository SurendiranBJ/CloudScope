"""AWS account project registry with principal-scoped ownership."""

import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.exc import IntegrityError

from app.persistence.database import get_db_session
from app.persistence.models import CloudProjectModel
from app.schemas import APIResponse
from app.security.dependencies import require_admin, require_viewer
from app.security.models import AuthenticatedUser

router = APIRouter(prefix="/projects", tags=["Projects"])


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=2000)
    account_id: Optional[str] = None
    role_arn: Optional[str] = Field(default=None, max_length=2048)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Project name must contain at least two characters")
        return value

    @field_validator("description")
    @classmethod
    def clean_description(cls, value: str) -> str:
        return value.strip()

    @field_validator("account_id")
    @classmethod
    def validate_account_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        normalized = value.strip()
        if not re.fullmatch(r"\d{12}", normalized):
            raise ValueError("AWS account ID must be exactly 12 digits")
        return normalized

    @field_validator("role_arn")
    @classmethod
    def validate_role_arn(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        normalized = value.strip()
        if not re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::\d{12}:role\/.+", normalized):
            raise ValueError("Enter a valid AWS IAM role ARN")
        return normalized

    @field_validator("role_arn")
    @classmethod
    def role_account_matches_project(cls, value: Optional[str], info):
        account_id = info.data.get("account_id")
        if value and account_id and value.split(":")[4] != account_id:
            raise ValueError("IAM role ARN account must match the AWS account ID")
        return value


class ProjectUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    description: Optional[str] = Field(default=None, max_length=2000)
    account_id: Optional[str] = None
    role_arn: Optional[str] = Field(default=None, max_length=2048)


def _owner(user: AuthenticatedUser) -> tuple[str, str]:
    return (user.issuer or "cloudscope", user.subject)


def _project_dict(row: CloudProjectModel) -> dict:
    return {
        "project_id": row.project_id,
        "name": row.name,
        "description": row.description or "",
        "account_id": row.account_id,
        "role_arn": row.role_arn,
        "status": row.status,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _get_owned(session, project_id: str, user: AuthenticatedUser) -> CloudProjectModel:
    row = session.query(CloudProjectModel).filter_by(
        project_id=project_id,
        owner_issuer=_owner(user)[0],
        owner_subject=_owner(user)[1],
    ).first()
    if row is None:
        # 404 prevents project ID enumeration across principals.
        raise HTTPException(status_code=404, detail="Project not found")
    return row


@router.get("", response_model=APIResponse[list[dict]])
def list_projects(user: AuthenticatedUser = Depends(require_viewer)):
    with get_db_session() as session:
        rows = session.query(CloudProjectModel).filter_by(
            owner_issuer=_owner(user)[0], owner_subject=_owner(user)[1], status="ACTIVE"
        ).order_by(CloudProjectModel.created_at.desc(), CloudProjectModel.project_id).all()
        data = [_project_dict(row) for row in rows]
    return APIResponse(success=True, message="Projects", timestamp=datetime.now(timezone.utc).isoformat(), data=data)


@router.post("", response_model=APIResponse[dict], status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, user: AuthenticatedUser = Depends(require_admin)):
    now = datetime.now(timezone.utc).isoformat()
    row = CloudProjectModel(
        project_id=str(uuid.uuid4()), owner_issuer=_owner(user)[0], owner_subject=_owner(user)[1],
        name=payload.name, description=payload.description, account_id=payload.account_id,
        role_arn=payload.role_arn, status="ACTIVE", created_at=now, updated_at=now,
        created_by=user.subject,
    )
    try:
        with get_db_session() as session:
            if row.account_id and session.query(CloudProjectModel).filter_by(
                owner_issuer=row.owner_issuer, owner_subject=row.owner_subject,
                account_id=row.account_id, status="ACTIVE",
            ).first():
                raise HTTPException(status_code=409, detail="A project for this AWS account already exists")
            session.add(row)
            session.flush()
            data = _project_dict(row)
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="A project for this AWS account already exists") from exc
    return APIResponse(success=True, message="Project created", timestamp=now, data=data)


@router.patch("/{project_id}", response_model=APIResponse[dict])
def update_project(project_id: str, payload: ProjectUpdate, user: AuthenticatedUser = Depends(require_admin)):
    values = payload.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status_code=422, detail="Provide at least one project field to update")
    # Reuse create validators for normalized account ID / role ARN and name.
    try:
        normalized = ProjectCreate(
            name=values.get("name", "Valid Project"),
            description=values.get("description", ""),
            account_id=values.get("account_id"), role_arn=values.get("role_arn"),
        )
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if "account_id" not in values or "role_arn" not in values:
        # Enforce matching values when changing just one side of the account/role pair.
        with get_db_session() as session:
            current = _get_owned(session, project_id, user)
            next_account = values.get("account_id", current.account_id)
            next_role = values.get("role_arn", current.role_arn)
            if next_role and next_account and next_role.split(":")[4] != next_account:
                raise HTTPException(status_code=422, detail="IAM role ARN account must match the AWS account ID")
    for key in values:
        if key == "name": values[key] = normalized.name
        elif key == "description": values[key] = normalized.description
        elif key in ("account_id", "role_arn"): values[key] = getattr(normalized, key)
    now = datetime.now(timezone.utc).isoformat()
    try:
        with get_db_session() as session:
            row = _get_owned(session, project_id, user)
            for key, value in values.items():
                setattr(row, key, value)
            row.updated_at = now
            session.flush()
            data = _project_dict(row)
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="A project for this AWS account already exists") from exc
    return APIResponse(success=True, message="Project updated", timestamp=now, data=data)


@router.delete("/{project_id}", response_model=APIResponse[dict])
def archive_project(project_id: str, user: AuthenticatedUser = Depends(require_admin)):
    now = datetime.now(timezone.utc).isoformat()
    with get_db_session() as session:
        row = _get_owned(session, project_id, user)
        row.status = "ARCHIVED"
        row.updated_at = now
        data = _project_dict(row)
    return APIResponse(success=True, message="Project archived", timestamp=now, data=data)
