"""IAM Policy and Trust Policy Evaluator.

Parses actual IAM Policy JSON documents and AssumeRole trust policies to
determine concrete permissions and access relationships WITHOUT relying on
heuristic policy/role/resource name matching.
"""

import json
import logging
import re
from fnmatch import fnmatchcase
from typing import Any, Dict, List, Set

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

        effect = stmt.get("Effect", "Deny")
        
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
    pattern = action_pattern.lower()
    target = target_action.lower()
    if pattern in ("*", "*:*"):
        return True
    return fnmatchcase(target, pattern)


def has_service_action(stmt_actions: List[str], service_prefix: str) -> bool:
    """Check if any action in the list grants access to the specified AWS service."""
    service = service_prefix.lower().rstrip(":")
    for action in stmt_actions:
        a = action.lower()
        if a in ("*", "*:*"):
            return True
        if a.startswith(f"{service}:") or fnmatchcase(f"{service}:sample", a):
            return True
    return False


def match_resource_arn(resource_pattern: str, target_res: Dict[str, Any]) -> bool:
    """Match a policy resource ARN pattern against an inventory resource object."""
    pattern = resource_pattern.strip()
    if pattern == "*":
        return True

    res_arn = target_res.get("arn", "")
    res_name = target_res.get("name", "")
    res_type = target_res.get("type", "")

    # Exact or fnmatch on full ARN
    if fnmatchcase(res_arn.lower(), pattern.lower()):
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

    return False


def evaluate_policy_allows_resources(policy_doc_input: Any, inventory_resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Determine which specific inventory resources a policy document grants access to.

    Evaluates Effect: Allow statements against each resource in the inventory.
    Returns a list of matched resource dictionaries.
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
    matched_ids: Set[str] = set()

    for res in inventory_resources:
        res_id = res.get("id") or res.get("name")
        res_type = res.get("type")
        if not res_id or not res_type or res_id in matched_ids:
            continue

        service_prefix = service_prefix_map.get(res_type)
        if not service_prefix:
            continue

        for stmt in statements:
            if stmt["Effect"] != "Allow":
                continue

            # Check if statement grants any action for this service
            if not has_service_action(stmt["Action"], service_prefix):
                continue

            # Check if statement Resource pattern covers this resource
            for res_pattern in stmt["Resource"]:
                if match_resource_arn(res_pattern, res):
                    matched_resources.append(res)
                    matched_ids.add(res_id)
                    break

            if res_id in matched_ids:
                break

    return matched_resources


def evaluate_assume_role_trust(
    trust_policy_input: Any,
    role_name: str,
    all_users: List[Dict[str, Any]],
    all_roles: List[Dict[str, Any]],
    account_id: str
) -> Dict[str, List[Dict[str, Any]]]:
    """Parse an AssumeRole trust policy to identify which Users and Roles can assume this Role.

    Returns:
        {
            "users": [user_dict, ...],
            "roles": [role_dict, ...]
        }
    """
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

        # Check action includes sts:AssumeRole
        actions = [a.lower() for a in stmt["Action"]]
        if not any(match_action(a, "sts:assumerole") for a in actions):
            continue

        principal = stmt.get("Principal", {})
        if not principal:
            continue

        # Check wildcard Principal: "*" or {"AWS": "*"}
        if principal == "*" or principal.get("AWS") == "*":
            for u in all_users:
                if u["id"] not in matched_user_ids:
                    result["users"].append(u)
                    matched_user_ids.add(u["id"])
            for r in all_roles:
                if r["name"] != role_name and r["name"] not in matched_role_names:
                    result["roles"].append(r)
                    matched_role_names.add(r["name"])
            continue

        aws_principals = principal.get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        elif not isinstance(aws_principals, list):
            aws_principals = []

        for p in aws_principals:
            p_str = str(p).strip()

            if p_str == "*":
                for u in all_users:
                    if u["id"] not in matched_user_ids:
                        result["users"].append(u)
                        matched_user_ids.add(u["id"])
                for r in all_roles:
                    if r["name"] != role_name and r["name"] not in matched_role_names:
                        result["roles"].append(r)
                        matched_role_names.add(r["name"])
                continue

            # Account root ARN: arn:aws:iam::<account_id>:root or pure account ID
            if p_str.endswith(":root") or (account_id and p_str == account_id):
                # Account root delegates to all active IAM users/roles in account
                for u in all_users:
                    if u["id"] not in matched_user_ids:
                        result["users"].append(u)
                        matched_user_ids.add(u["id"])
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
                if u_name in user_name_map and user_name_map[u_name]["id"] not in matched_user_ids:
                    u_obj = user_name_map[u_name]
                    result["users"].append(u_obj)
                    matched_user_ids.add(u_obj["id"])
                elif p_str in user_arn_map and user_arn_map[p_str]["id"] not in matched_user_ids:
                    u_obj = user_arn_map[p_str]
                    result["users"].append(u_obj)
                    matched_user_ids.add(u_obj["id"])

    return result
