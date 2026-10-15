"""Request and scan scope used to isolate account-backed data by project."""

from contextvars import ContextVar, Token
from typing import Optional

_project_id: ContextVar[Optional[str]] = ContextVar("cloudscope_project_id", default=None)


def get_project_id() -> Optional[str]:
    return _project_id.get()


def set_project_id(project_id: Optional[str]) -> Token:
    return _project_id.set(project_id)


def reset_project_id(token: Token) -> None:
    _project_id.reset(token)


def get_project_scope_key() -> str:
    return get_project_id() or "global"
