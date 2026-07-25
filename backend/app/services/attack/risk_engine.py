import logging
from typing import Dict, Any

logger = logging.getLogger("scanner")

def score_user_risk(user: Dict[str, Any]) -> int:
    score = 10
    
    # 1. Check MFA
    if not user.get('mfaEnabled', True):
        score += 35
        
    # 2. Check Admin policies
    policies = user.get('policies', [])
    for p in policies:
        if "AdministratorAccess" in p or "Admin" in p:
            score += 45
            break
            
    # 3. Check membership scope
    if len(user.get('groups', [])) > 2:
        score += 10
        
    return min(99, score)

def score_role_risk(role: Dict[str, Any]) -> int:
    score = 15
    
    # Check Admin/PowerUser assume configurations
    name = role.get('name', '')
    if "Admin" in name or "Root" in name:
        score += 50
    elif "Profile" in name or "Runner" in name:
        score += 30
        
    # Parse trust policy statements for wildcard principals
    trust = role.get('trustPolicy', '{}')
    if '"Principal": "*"' in trust or '"AWS": "*"' in trust:
        score += 40
        
    return min(99, score)

def score_resource_risk(res: Dict[str, Any]) -> int:
    score = 20
    rtype = res.get('type')
    
    if rtype == 'S3':
        details = res.get('details', {})
        # Public S3 is critical risk
        if not details.get('public_blocked', True):
            score += 70
        # No encryption
        if not details.get('encrypted', True):
            score += 15
    elif rtype == 'Secrets':
        details = res.get('details', {})
        # Secrets Manager without rotation
        if not details.get('rotation_enabled', False):
            score += 45
    elif rtype == 'EC2':
        details = res.get('details', {})
        # Has profile
        if details.get('iam_role_name') != 'None':
            score += 20
            
    return min(99, score)
