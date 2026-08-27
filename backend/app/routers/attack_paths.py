from fastapi import APIRouter, HTTPException
from typing import List
from app.schemas import APIResponse, AttackPath
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Attack Paths"])

@router.get("/attack-paths", response_model=APIResponse[List[AttackPath]])
def get_attack_paths():
    data = cache.get("v1:attack-paths")
    if not data:
        # Cache is cold — trigger async scan if not already running and
        # return an empty list immediately so the frontend can poll.
        if not scan_manager.is_running:
            scan_manager.trigger_async_scan()
        data = []
        
    return APIResponse(
        success=True,
        message="Attack Paths threat pathways retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )

@router.get("/attack-paths/{id}", response_model=APIResponse[AttackPath])
def get_attack_path_by_id(id: str):
    data = cache.get("v1:attack-paths") or []
    match_path = next((p for p in data if p['id'] == id), None)
    if not match_path:
        raise HTTPException(status_code=404, detail=f"Attack path with id '{id}' not found")
        
    return APIResponse(
        success=True,
        message=f"Attack path details for '{id}' retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=match_path
    )
