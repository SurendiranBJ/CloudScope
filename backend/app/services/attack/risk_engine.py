import logging
import json
from typing import Dict, Any

logger = logging.getLogger("scanner")

def _has_wildcard_permissions(policy_docs: list) -> bool:
    """Return True if any of the provided policy document JSON strings grant
    a wildcard Action (*) on a wildcard Resource (*).

    Args:
        policy_docs: A list of IAM policy document strings (JSON). Callers are
            responsible for passing actual document strings, not policy names.
    """
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

def score_user_risk(user: Dict[str, Any], policy_doc_map: Dict[str, str]) -> int:
    """Score the risk of an IAM user.

    Args:
        user: IAM user dict as produced by iam_service.collect_users().
        policy_doc_map: Mapping of policy name -> JSON document string for
            every customer-managed policy collected by
            iam_service.collect_policies(). AWS-managed policies (e.g.
            AdministratorAccess) will not be present in this map because
            collect_policies() only fetches Scope='Local' policies.
    """
    score = 10

    if not user.get('mfaEnabled', True):
        score += 35

    policy_names = user.get('policies', [])

    # Resolve names that have a fetched document to their actual JSON content
    # so _has_wildcard_permissions() can inspect real permissions.
    resolved_docs = [
        policy_doc_map[name]
        for name in policy_names
        if name in policy_doc_map
    ]

    if _has_wildcard_permissions(resolved_docs):
        score += 45
    else:
        # Fallback for policies without a fetched document (i.e. AWS-managed
        # policies such as AdministratorAccess that are not returned by
        # Scope='Local'): use name-substring heuristics.
        if any("AdministratorAccess" in p or "Admin" in p for p in policy_names):
            score += 30

    if len(user.get('groups', [])) > 2:
        score += 10

    return min(99, score)

def score_role_risk(role: Dict[str, Any], policy_doc_map: Dict[str, str]) -> int:
    """Score the risk of an IAM role.

    Args:
        role: IAM role dict as produced by iam_service.collect_roles().
        policy_doc_map: Mapping of policy name -> JSON document string for
            every customer-managed policy collected by
            iam_service.collect_policies(). AWS-managed policies will not be
            present in this map (see score_user_risk docstring).
    """
    score = 15

    name = role.get('name', '')
    if "Admin" in name or "Root" in name:
        score += 30

    trust = role.get('trustPolicy', '{}')
    if '"Principal": "*"' in trust or '"AWS": "*"' in trust:
        score += 40

    attached_policy_names = role.get('attachedPolicies', [])

    # Resolve names that have a fetched document to their actual JSON content.
    resolved_docs = [
        policy_doc_map[p_name]
        for p_name in attached_policy_names
        if p_name in policy_doc_map
    ]

    if _has_wildcard_permissions(resolved_docs):
        score += 25
    # No name-heuristic fallback for roles: the role name already contributes
    # +30 above via the Admin/Root substring check, which is the appropriate
    # signal for roles where no document is available.

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
