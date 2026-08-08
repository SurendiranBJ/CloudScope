import logging
import json
from typing import Dict, Any

logger = logging.getLogger("scanner")

def _has_wildcard_permissions(policy_docs: list) -> bool:
    for doc_str in policy_docs:
        try:
            doc = json.loads(doc_str)
            statements = doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if stmt.get('Effect') == 'Allow':
                    actions = stmt.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    resources = stmt.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    
                    if any(a == '*' or a == '*:*' for a in actions) and any(r == '*' for r in resources):
                        return True
        except Exception:
            continue
    return False

def score_user_risk(user: Dict[str, Any]) -> int:
    score = 10
    
    if not user.get('mfaEnabled', True):
        score += 35
        
    policies = user.get('policies', [])
    if _has_wildcard_permissions(policies):
        score += 45
    elif any("AdministratorAccess" in p or "Admin" in p for p in policies):
        score += 30
            
    if len(user.get('groups', [])) > 2:
        score += 10
        
    return min(99, score)

def score_role_risk(role: Dict[str, Any]) -> int:
    score = 15
    
    name = role.get('name', '')
    if "Admin" in name or "Root" in name:
        score += 30
        
    trust = role.get('trustPolicy', '{}')
    if '"Principal": "*"' in trust or '"AWS": "*"' in trust:
        score += 40
        
    attached_policies = role.get('attachedPolicies', [])
    if _has_wildcard_permissions(attached_policies):
        score += 25
        
    return min(99, score)

def score_resource_risk(res: Dict[str, Any]) -> int:
    score = 20
    rtype = res.get('type')
    
    if rtype == 'S3':
        details = res.get('details', {})
        if not details.get('public_blocked', True):
            score += 70
        if not details.get('encrypted', True):
            score += 15
    elif rtype == 'Secrets':
        details = res.get('details', {})
        if not details.get('rotation_enabled', False):
            score += 45
    elif rtype == 'EC2':
        details = res.get('details', {})
        if details.get('iam_role_name') != 'None':
            score += 20
    elif rtype == 'RDS':
        details = res.get('details', {})
        if details.get('publicly_accessible', False):
            score += 60
        if not details.get('storage_encrypted', True):
            score += 30
    elif rtype == 'DynamoDB':
        details = res.get('details', {})
        if not details.get('pitr_enabled', True):
            score += 25
            
    return min(99, score)
