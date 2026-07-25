from fastapi import APIRouter
from typing import List
from app.schemas import APIResponse, IAMRole
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["AWS Resources"])

@router.get("/roles", response_model=APIResponse[List[IAMRole]])
def get_iam_roles():
    data = cache.get("v1:roles")
    if not data:
        scan_manager.run_scan()
        data = cache.get("v1:roles") or []
        
    return APIResponse(
        success=True,
        message="IAM Roles collection retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
