from fastapi import APIRouter
from typing import List
from app.schemas import APIResponse, IAMUser
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["AWS Resources"])

@router.get("/users", response_model=APIResponse[List[IAMUser]])
def get_iam_users():
    data = cache.get("v1:users")
    if not data:
        scan_manager.run_scan()
        data = cache.get("v1:users") or []
        
    return APIResponse(
        success=True,
        message="IAM Users collection retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
