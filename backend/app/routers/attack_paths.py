from fastapi import APIRouter, HTTPException
from typing import List
from datetime import datetime
from app.schemas import APIResponse, AttackPath
from app.services.scanner.scan_manager import scan_manager
from app.services.scanner.current_snapshot import (
    get_current_attack_paths,
    get_current_snapshot_id,
    get_current_snapshot_published_at,
    has_published_snapshot,
)

router = APIRouter(tags=["Attack Paths"])

@router.get("/attack-paths", response_model=APIResponse[List[AttackPath]])
def get_attack_paths():
    data = get_current_attack_paths()
    if not data and not has_published_snapshot() and not scan_manager.is_running:
        scan_manager.trigger_async_scan()
        
    return APIResponse(
        success=True,
        message="Attack Paths threat pathways retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=data
    )

@router.get("/attack-paths/{id}", response_model=APIResponse[AttackPath])
def get_attack_path_by_id(id: str):
    data = get_current_attack_paths()
    match_path = next((p for p in data if p.get('id') == id), None)
    if not match_path:
        raise HTTPException(status_code=404, detail=f"Attack path with id '{id}' not found")
        
    return APIResponse(
        success=True,
        message=f"Attack path details for '{id}' retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        snapshot_id=get_current_snapshot_id(),
        snapshot_published_at=get_current_snapshot_published_at(),
        data=match_path
    )

