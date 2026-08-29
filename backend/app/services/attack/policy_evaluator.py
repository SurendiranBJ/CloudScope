"""
IAM Policy, Trust Policy, and Resource ARN Evaluator.

Parses actual IAM Policy JSON documents and AssumeRole trust policies to
determine concrete permissions, access relationships, and risk factors
WITHOUT relying on heuristic policy/role/resource name matching.
"""

import json
import logging
import re
from fnmatch import fnmatchcase
from typing import Any, Dict, List, Set, Tuple
from app.services.risk.risk_constants import (
    WEIGHTS,
    DANGEROUS_ESCALATION_ACTIONS,
    BROAD_ADMIN_ACTIONS
)

logger = logging.getLogger("scanner")


def parse_policy_document(doc_input: Any) -> List[Dict[str, Any]]:
    """Parse and normalize an IAM policy document into a list of statement dicts."""
    if not doc_input:
        return []

    doc = doc_input
    if isinstance(doc_input, str):
        try:
            doc = json.loads(doc_input)
        except Exception as e:
            logger.debug(f"Failed to parse policy JSON document: {e}")
            return []

    if not isinstance(doc, dict):
        return []

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        statements = []

    normalized = []
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        raw_effect = str(stmt.get("Effect", "Deny")).strip()
        effect = "Allow" if raw_effect.lower() == "allow" else "Deny"

        # Normalize Action
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        elif not isinstance(actions, list):
            actions = []

        # Normalize NotAction
        not_actions = stmt.get("NotAction", [])
        if isinstance(not_actions, str):
            not_actions = [not_actions]
        elif not isinstance(not_actions, list):
            not_actions = []

        # Normalize Resource
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        elif not isinstance(resources, list):
            resources = []

        # Normalize NotResource
        not_resources = stmt.get("NotResource", [])
        if isinstance(not_resources, str):
            not_resources = [not_resources]
        elif not isinstance(not_resources, list):
            not_resources = []

        normalized.append({
            "Effect": effect,
            "Action": actions,
            "NotAction": not_actions,
            "Resource": resources,
            "NotResource": not_resources,
            "Condition": stmt.get("Condition", {}),
            "Principal": stmt.get("Principal", {})
        })

    return normalized


def match_action(action_pattern: str, target_action: str) -> bool:
    """Check if an IAM action pattern matches a target action."""
    pattern = action_pattern.lower().strip()
    target = target_action.lower().strip()
    if pattern in ("*", "*:*"):
        return True
    return fnmatchcase(target, pattern)


def has_service_action(stmt_actions: List[str], not_actions: List[str], service_prefix: str) -> bool:
    """Check if actions grant access to the specified AWS service (taking NotAction into account)."""
    service = service_prefix.lower().rstrip(":")
    
    # If NotAction is used with an Allow statement
    if not_actions:
        # If the target service is NOT excluded by NotAction, it is permitted
        if not any(a.lower().startswith(f"{service}:") for a in not_actions):
            return True

    for action in stmt_actions:
        a = action.lower().strip()
        if a in ("*", "*:*"):
            return True
        if a.startswith(f"{service}:") or fnmatchcase(f"{service}:action", a):
            return True
    return False


def match_resource_arn(resource_pattern: str, not_resources: List[str], target_res: Dict[str, Any]) -> bool:
    """Match a policy resource ARN pattern against an inventory resource object."""
    res_arn = target_res.get("arn", "").strip()
    res_name = target_res.get("name", "").strip()
    res_type = target_res.get("type", "").strip()

    # Check NotResource exclusions
    if not_resources:
        for nr in not_resources:
            nr_clean = nr.strip()
            if fnmatchcase(res_arn.lower(), nr_clean.lower()):
                return False

    pattern = resource_pattern.strip()
    if pattern == "*":
        return True

    # Exact or glob pattern match on full ARN
    if res_arn and fnmatchcase(res_arn.lower(), pattern.lower()):
        return True

    # S3 specific matching: arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/*
    if res_type == "S3":
        clean_pattern = pattern.rstrip("/*").rstrip("/")
        if clean_pattern.lower() == f"arn:aws:s3:::{res_name}".lower():
            return True
        if fnmatchcase(f"arn:aws:s3:::{res_name}".lower(), clean_pattern.lower()):
            return True

    # Secrets Manager specific matching: arn contains secret name prefix
    if res_type == "Secrets":
        if pattern.endswith("*"):
            prefix = pattern.rstrip("*")
            if res_arn.lower().startswith(prefix.lower()):
                return True
        if f":secret:{res_name}" in pattern:
            return True

    # DynamoDB specific matching: arn:aws:dynamodb:...:table/TableName
    if res_type == "DynamoDB":
        if f":table/{res_name}" in pattern:
            return True

    # RDS specific matching: arn:aws:rds:...:db:DbInstanceIdentifier
    if res_type == "RDS":
        if f":db:{res_name}" in pattern:
            return True

    # EC2 specific matching: arn:aws:ec2:...:instance/i-xxx
    if res_type == "EC2":
        if f":instance/{res_name}" in pattern:
            return True

    # Lambda specific matching: arn:aws:lambda:...:function:FuncName
    if res_type == "Lambda":
        if f":function:{res_name}" in pattern:
            return True

    return False


def evaluate_policy_allows_resources(policy_doc_input: Any, inventory_resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Determine which specific inventory resources a policy document grants access to.

    Evaluates Effect: Allow statements against each resource in the inventory,
    and ensures explicit DENY statements properly override any ALLOW.
    """
    statements = parse_policy_document(policy_doc_input)
    if not statements:
        return []

    service_prefix_map = {
        "S3": "s3",
        "Secrets": "secretsmanager",
        "RDS": "rds",
        "DynamoDB": "dynamodb",
        "EC2": "ec2",
        "Lambda": "lambda"
    }

    matched_resources: List[Dict[str, Any]] = []

    for res in inventory_resources:
        res_id = res.get("id") or res.get("name")
        res_type = res.get("type")
        if not res_id or not res_type:
            continue

        service_prefix = service_prefix_map.get(res_type)
        if not service_prefix:
            continue

        is_allowed = False
        is_denied = False

        for stmt in statements:
            effect = stmt["Effect"]
            actions = stmt["Action"]
            not_actions = stmt.get("NotAction", [])
            resources = stmt["Resource"]
            not_resources = stmt.get("NotResource", [])

            # Check if this statement applies to this resource's service
            service_matches = has_service_action(actions, not_actions, service_prefix)
            if not service_matches:
                continue

            # Check if this statement applies to this resource's ARN
            resource_matches = False
            for res_pattern in (resources or ["*"]):
                if match_resource_arn(res_pattern, not_resources, res):
                    resource_matches = True
                    break

            if resource_matches:
                if effect == "Deny":
                    is_denied = True
                    break  # Explicit Deny wins immediately
                elif effect == "Allow":
                    is_allowed = True

        if is_allowed and not is_denied:
            matched_resources.append(res)

    return matched_resources


def evaluate_policy_document_risk(policy_docs: List[Any]) -> Dict[str, Any]:
    """Inspect actual parsed IAM policy statements to extract concrete risk factors.
    Returns:
        {
            "has_wildcard_action": bool,
            "has_wildcard_resource": bool,
            "has_privilege_escalation": bool,
            "factors": [{"code": str, "points": int, "reason": str}]
        }
    """
    factors: List[Dict[str, Any]] = []
    has_wildcard_act = False
    has_wildcard_res = False
    has_admin_perm = False
    has_priv_esc = False

    for doc in policy_docs:
        statements = parse_policy_document(doc)
        for stmt in statements:
            if stmt["Effect"] != "Allow":
                continue

            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])

            # Check wildcard Action
            if any(a in ("*", "*:*") for a in actions):
                has_wildcard_act = True

            # Check wildcard Resource
            if any(r == "*" for r in resources):
                has_wildcard_res = True

            # Check broad administrative actions
            if any(a.lower() in BROAD_ADMIN_ACTIONS for a in actions):
                has_admin_perm = True

            # Check dangerous privilege escalation actions
            for act in actions:
                act_clean = act.lower().strip()
                if act_clean in DANGEROUS_ESCALATION_ACTIONS:
                    has_priv_esc = True
                    break

    if has_wildcard_act and has_wildcard_res:
        factors.append({
            "code": "WILDCARD_ALLOW_ALL",
            "points": WEIGHTS["WILDCARD_ALLOW_ALL"],
            "reason": "Policy grants unconditional Administrator access (Action: * on Resource: *)."
        })
    else:
        if has_wildcard_act:
            factors.append({
                "code": "WILDCARD_ACTION",
                "points": WEIGHTS["WILDCARD_ACTION"],
                "reason": "Policy grants wildcard Action (*) permissions."
            })
        if has_wildcard_res:
            factors.append({
                "code": "WILDCARD_RESOURCE",
                "points": WEIGHTS["WILDCARD_RESOURCE"],
                "reason": "Policy grants broad Resource (*) scope without resource ARN constraints."
            })
        if has_admin_perm:
            factors.append({
                "code": "FULL_ADMIN_PERMISSION",
                "points": WEIGHTS["FULL_ADMIN_PERMISSION"],
                "reason": "Policy includes broad administrative service control (e.g., iam:*, sts:*)."
            })

    if has_priv_esc:
        factors.append({
            "code": "PRIVILEGE_ESCALATION_PERMS",
            "points": WEIGHTS["PRIVILEGE_ESCALATION_PERMS"],
            "reason": "Policy grants dangerous IAM privilege escalation capabilities (e.g., iam:PassRole, iam:AttachRolePolicy)."
        })

    return {
        "has_wildcard_action": has_wildcard_act,
        "has_wildcard_resource": has_wildcard_res,
        "has_privilege_escalation": has_priv_esc,
        "factors": factors
    }


def evaluate_trust_policy_risk(trust_policy_input: Any) -> Dict[str, Any]:
    """Inspect an AssumeRole trust policy to extract structured trust risk factors."""
    factors: List[Dict[str, Any]] = []
    statements = parse_policy_document(trust_policy_input)

    for stmt in statements:
        if stmt["Effect"] != "Allow":
            continue

        actions = [a.lower() for a in stmt.get("Action", [])]
        if not any(match_action(a, "sts:assumerole") for a in actions):
            continue

        principal = stmt.get("Principal", {})
        
        # Check wildcard Principal: "*" or {"AWS": "*"}
        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            factors.append({
                "code": "WILDCARD_TRUST_PRINCIPAL",
                "points": WEIGHTS["WILDCARD_TRUST_PRINCIPAL"],
                "reason": "AssumeRole trust policy contains a wildcard Principal (*), allowing any AWS entity to assume this role."
            })
            continue

        if isinstance(principal, dict):
            aws_p = principal.get("AWS", [])
            if isinstance(aws_p, str):
                aws_p = [aws_p]
            elif not isinstance(aws_p, list):
                aws_p = []

            for p in aws_p:
                if str(p).strip() == "*":
                    factors.append({
                        "code": "WILDCARD_TRUST_PRINCIPAL",
                        "points": WEIGHTS["WILDCARD_TRUST_PRINCIPAL"],
                        "reason": "AssumeRole trust policy specifies AWS: '*' principal."
                    })
                    break

            # Service Principal check (e.g. ec2.amazonaws.com, lambda.amazonaws.com)
            service_p = principal.get("Service", [])
            if isinstance(service_p, str):
                service_p = [service_p]
            elif not isinstance(service_p, list):
                service_p = []

            if any(s == "*" for s in service_p):
                factors.append({
                    "code": "UNRESTRICTED_SERVICE_TRUST",
                    "points": WEIGHTS["UNRESTRICTED_SERVICE_TRUST"],
                    "reason": "AssumeRole trust policy allows unrestricted Service principal."
                })

    return {
        "factors": factors
    }


def evaluate_assume_role_trust(
    trust_policy_input: Any,
    role_name: str,
    all_users: List[Dict[str, Any]],
    all_roles: List[Dict[str, Any]],
    account_id: str
) -> Dict[str, List[Dict[str, Any]]]:
    """Parse an AssumeRole trust policy to identify which Users and Roles can assume this Role."""
    result: Dict[str, List[Dict[str, Any]]] = {"users": [], "roles": []}
    statements = parse_policy_document(trust_policy_input)
    if not statements:
        return result

    user_name_map = {u["name"]: u for u in all_users}
    user_arn_map = {u["arn"]: u for u in all_users}
    role_name_map = {r["name"]: r for r in all_roles if r["name"] != role_name}
    role_arn_map = {r["arn"]: r for r in all_roles if r["name"] != role_name}

    matched_user_ids: Set[str] = set()
    matched_role_names: Set[str] = set()

    for stmt in statements:
        if stmt["Effect"] != "Allow":
            continue

        actions = [a.lower() for a in stmt["Action"]]
        if not any(match_action(a, "sts:assumerole") for a in actions):
            continue

        principal = stmt.get("Principal", {})
        if not principal:
            continue

        if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
            for u in all_users:
                u_id = u.get("id") or u.get("name")
                if u_id not in matched_user_ids:
                    result["users"].append(u)
                    matched_user_ids.add(u_id)
            for r in all_roles:
                if r["name"] != role_name and r["name"] not in matched_role_names:
                    result["roles"].append(r)
                    matched_role_names.add(r["name"])
            continue

        aws_principals = principal.get("AWS", []) if isinstance(principal, dict) else []
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        elif not isinstance(aws_principals, list):
            aws_principals = []

        for p in aws_principals:
            p_str = str(p).strip()

            if p_str == "*":
                for u in all_users:
                    u_id = u.get("id") or u.get("name")
                    if u_id not in matched_user_ids:
                        result["users"].append(u)
                        matched_user_ids.add(u_id)
                for r in all_roles:
                    if r["name"] != role_name and r["name"] not in matched_role_names:
                        result["roles"].append(r)
                        matched_role_names.add(r["name"])
                continue

            # Account root ARN or Account ID
            if p_str.endswith(":root") or (account_id and p_str == account_id):
                for u in all_users:
                    u_id = u.get("id") or u.get("name")
                    if u_id not in matched_user_ids:
                        result["users"].append(u)
                        matched_user_ids.add(u_id)
                for r in all_roles:
                    if r["name"] != role_name and r["name"] not in matched_role_names:
                        result["roles"].append(r)
                        matched_role_names.add(r["name"])
                continue

            # Specific Role ARN
            if ":role/" in p_str:
                r_name = p_str.split("/")[-1]
                if r_name in role_name_map and r_name not in matched_role_names:
                    result["roles"].append(role_name_map[r_name])
                    matched_role_names.add(r_name)
                elif p_str in role_arn_map and role_arn_map[p_str]["name"] not in matched_role_names:
                    matched_r = role_arn_map[p_str]
                    result["roles"].append(matched_r)
                    matched_role_names.add(matched_r["name"])

            # Specific User ARN
            elif ":user/" in p_str:
                u_name = p_str.split("/")[-1]
                if u_name in user_name_map:
                    u_obj = user_name_map[u_name]
                    u_id = u_obj.get("id") or u_obj.get("name")
                    if u_id not in matched_user_ids:
                        result["users"].append(u_obj)
                        matched_user_ids.add(u_id)
                elif p_str in user_arn_map:
                    u_obj = user_arn_map[p_str]
                    u_id = u_obj.get("id") or u_obj.get("name")
                    if u_id not in matched_user_ids:
                        result["users"].append(u_obj)
                        matched_user_ids.add(u_id)

    return result
