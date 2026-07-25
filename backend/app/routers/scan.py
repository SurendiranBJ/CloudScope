from fastapi import APIRouter
from app.schemas import APIResponse
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Scan"])

@router.post("/scan", response_model=APIResponse[dict])
def trigger_manual_scan():
    result = scan_manager.run_scan()
    return APIResponse(
        success=True if result.get("status") in ["success", "skipped"] else False,
        message="AWS Scan run command executed successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=result
    )
