from fastapi import APIRouter
from app.schemas import APIResponse
from app.cache import cache
from datetime import datetime

router = APIRouter(tags=["Reports"])

@router.get("/reports", response_model=APIResponse[dict])
def get_reports_summary():
    # Return formatted compliance logs matching frontend expect
    reports_data = {
        "compliance": [
            {"name": "CIS AWS Foundations Benchmark", "score": 72, "details": "Passed: 28 checks | Failed: 11 checks | Ignored: 3"},
            {"name": "SOC 2 Type II Compliance Framework", "score": 86, "details": "Passed: 44 checks | Failed: 7 checks | Ignored: 0"},
            {"name": "HIPAA Security Controls Audit", "score": 91, "details": "Passed: 19 checks | Failed: 2 checks | Ignored: 1"},
            {"name": "PCI-DSS v4.0 Merchant Standard", "score": 65, "details": "Passed: 30 checks | Failed: 16 checks | Ignored: 2"}
        ],
        "summary": {
            "score": "84%",
            "grade": "Good",
            "findings_count": 5
        }
    }
    return APIResponse(
        success=True,
        message="Compliance audits and reports summary retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=reports_data
    )
