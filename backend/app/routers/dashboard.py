from fastapi import APIRouter
from app.schemas import APIResponse, DashboardData
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager
from datetime import datetime

router = APIRouter(tags=["Dashboard"])


@router.get("/dashboard", response_model=APIResponse[DashboardData])
def get_dashboard_summary():
    users = cache.get("v1:users") or []
    roles = cache.get("v1:roles") or []
    policies = cache.get("v1:policies") or []
    resources = cache.get("v1:resources") or []
    risks = cache.get("v1:risks") or []
    paths = cache.get("v1:attack-paths") or []
    alerts = cache.get("v1:alerts") or []
    global_posture = cache.get("v1:global_posture")
    
    # If cache is completely empty and scanner is idle, trigger background scan
    if not users and not roles and not scan_manager.is_running:
        scan_manager.trigger_async_scan()

    critical_count = sum(1 for r in risks if r.get('severity') == 'critical' or r.get('riskScore', 0) >= 80)
    high_count = sum(1 for r in risks if r.get('severity') == 'high' or (60 <= r.get('riskScore', 0) < 80))
    medium_count = sum(1 for r in risks if r.get('severity') == 'medium' or (40 <= r.get('riskScore', 0) < 60))
    low_count = sum(1 for r in risks if r.get('severity') == 'low' or (0 < r.get('riskScore', 0) < 40))

    score_val = global_posture.get("overall_score", 85) if global_posture else (100 - min(60, critical_count * 15 + high_count * 5) if risks else 100)

    # Real Resource Breakdown
    res_breakdown = [
        {"type": "IAM Users", "count": len(users)},
        {"type": "IAM Roles", "count": len(roles)},
        {"type": "IAM Policies", "count": len(policies)},
        {"type": "S3 Buckets", "count": sum(1 for r in resources if r.get('type') == 'S3')},
        {"type": "EC2 Instances", "count": sum(1 for r in resources if r.get('type') == 'EC2')},
        {"type": "Lambda Functions", "count": sum(1 for r in resources if r.get('type') == 'Lambda')},
        {"type": "Secrets", "count": sum(1 for r in resources if r.get('type') == 'Secrets')},
        {"type": "RDS Databases", "count": sum(1 for r in resources if r.get('type') == 'RDS')},
        {"type": "DynamoDB Tables", "count": sum(1 for r in resources if r.get('type') == 'DynamoDB')}
    ]
    res_breakdown = [r for r in res_breakdown if r["count"] > 0]

    # Top Risky Identities
    all_identities = users + roles
    sorted_identities = sorted(all_identities, key=lambda x: x.get('riskScore', 0), reverse=True)
    top_identities = [
        {
            "name": x.get('name') or x.get('username', 'Unknown'),
            "type": "User" if "mfaEnabled" in x else "Role",
            "riskScore": x.get('riskScore', 0),
            "arn": x.get('arn', '')
        }
        for x in sorted_identities[:5]
        if x.get('riskScore', 0) > 0
    ]

    # Critical Attack Paths
    critical_paths = [p for p in paths if p.get('severity') in ['critical', 'high']][:5]

    data = {
        "securityScore": f"{score_val} / 100",
        "stats": {
            "users": len(users),
            "roles": len(roles),
            "policies": len(policies),
            "risks": critical_count + high_count + medium_count,
            "paths": len(paths),
            "resources": len(resources)
        },
        "riskDistribution": [
            {"name": "Critical", "value": critical_count, "color": "#EF4444"},
            {"name": "High", "value": high_count, "color": "#F59E0B"},
            {"name": "Medium", "value": medium_count, "color": "#3B82F6"},
            {"name": "Low", "value": low_count, "color": "#10B981"}
        ],
        "recentAlerts": alerts[:5],
        "criticalPaths": critical_paths,
        "recommendations": [
            {"title": "Enforce Least Privilege", "desc": "Restrict wildcard IAM policies and apply resource-specific ARN constraints."},
            {"title": "Enable MFA for All Users", "desc": "Enforce hardware or virtual MFA across all administrative and developer user accounts."},
            {"title": "Block Public S3 Access", "desc": "Enable S3 Block Public Access to prevent accidental internet-wide data exposure."}
        ],
        "lastScan": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "duration_seconds": 2.5,
            "resources_found": len(resources),
            "risks_found": critical_count + high_count + medium_count,
            "graph_nodes_count": len(resources),
            "graph_edges_count": len(paths),
            "scanned_regions": ["us-east-1"]
        },
        "topRiskyIdentities": top_identities,
        "resourceBreakdown": res_breakdown
    }

    return APIResponse(
        success=True,
        message="Dashboard summary retrieved successfully",
        timestamp=datetime.utcnow().isoformat() + "Z",
        data=data
    )
