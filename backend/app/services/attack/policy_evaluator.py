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
from typing import Any, Dict, List, Set, Tuple, Optional
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
    account_id: str,
    policy_doc_map: Optional[Dict[str, str]] = None,
    all_groups: Any = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Compatibility wrapper around evaluate_assume_role_trust_with_evidence.

    DEPRECATED: Prefer evaluate_assume_role_trust_with_evidence.
    Delegates completely to the authoritative evaluator.
    Returns only principals with verified call permissions and definitive trust.
    NEVER independently expands wildcard Principal: '*' to unauthorized callers.
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}" if account_id else f"role/{role_name}"
    for r in all_roles:
        if r.get("name") == role_name and r.get("arn"):
            role_arn = r["arn"]
            break

    ev_res = evaluate_assume_role_trust_with_evidence(
        trust_policy_input=trust_policy_input,
        role_name=role_name,
        role_arn=role_arn,
        all_users=all_users,
        all_roles=all_roles,
        account_id=account_id,
        policy_doc_map=policy_doc_map or {},
        all_groups=all_groups,
    )
    valid_users = [
        u["principal"] for u in ev_res.get("users", [])
        if u.get("evidence", {}).get("trust_status") == "definitive"
        and u.get("evidence", {}).get("call_permission_verified")
    ]
    valid_roles = [
        r["principal"] for r in ev_res.get("roles", [])
        if r.get("evidence", {}).get("trust_status") == "definitive"
        and r.get("evidence", {}).get("call_permission_verified")
    ]
    return {"users": valid_users, "roles": valid_roles}


# ─── Authoritative Trust + Call-Permission Evaluator ────────────────────────

# ─── Group Normalization and Effective Policy Collection ─────────────────────

def _normalize_group_key(key: Any) -> str:
    """Extract a canonical normalized key (lowercase string) from a group name, ARN, or dict."""
    if not key:
        return ""
    if isinstance(key, dict):
        s = key.get("name") or key.get("GroupName") or key.get("id") or key.get("arn") or ""
    else:
        s = str(key)
    s = s.strip()
    if ":group/" in s:
        s = s.split(":group/")[-1]
    elif "/" in s:
        s = s.split("/")[-1]
    return s.lower().strip()


def _build_normalized_group_map(all_groups: Any) -> Dict[str, Dict[str, Any]]:
    """Index groups by multiple normalized representations:
    lowercase short name, full ARN, id.
    """
    g_map: Dict[str, Dict[str, Any]] = {}
    if not all_groups:
        return g_map
    group_list = getattr(all_groups, "groups", all_groups) if not isinstance(all_groups, (list, dict)) else all_groups
    if isinstance(group_list, dict):
        group_list = list(group_list.values())

    for g in group_list:
        if not isinstance(g, dict):
            continue
        gname = g.get("name") or g.get("GroupName") or g.get("id") or ""
        garn = g.get("arn") or ""
        gid = g.get("id") or ""

        for key in [gname, garn, gid]:
            if key:
                norm = _normalize_group_key(key)
                if norm:
                    g_map[norm] = g
                g_map[str(key).strip().lower()] = g
    return g_map


def get_effective_identity_policy_documents(
    principal: Dict[str, Any],
    policy_doc_map: Dict[str, str],
    all_groups: Any = None,
) -> List[str]:
    """Collect ALL applicable IAM policy documents for a principal.

    Includes:
    - Direct attached managed policies
    - Direct inline policy documents
    - Inherited group attached managed policies (normalized lookup)
    - Inherited group inline policy documents
    """
    all_docs: List[str] = []

    # 1. Direct managed policies
    p_policy_names = (
        principal.get("policies", []) +
        principal.get("attachedPolicies", [])
    )
    for pname in p_policy_names:
        clean = pname.replace("[inline] ", "")
        doc = policy_doc_map.get(pname) or policy_doc_map.get(clean)
        if doc:
            all_docs.append(doc)

    # 2. Direct inline policy documents
    for in_doc in principal.get("inlinePolicyDocuments", {}).values():
        if in_doc:
            all_docs.append(in_doc)

    # 3. Inherited group policies (for Users)
    user_groups = principal.get("groups", [])
    if user_groups and all_groups:
        g_map = _build_normalized_group_map(all_groups)
        for g_ref in user_groups:
            norm_key = _normalize_group_key(g_ref)
            g_obj = g_map.get(norm_key)
            if not g_obj:
                continue
            g_pnames = g_obj.get("attachedPolicies", []) + g_obj.get("policies", [])
            for pname in g_pnames:
                clean = pname.replace("[inline] ", "")
                doc = policy_doc_map.get(pname) or policy_doc_map.get(clean)
                if doc:
                    all_docs.append(doc)
            for in_doc in g_obj.get("inlinePolicyDocuments", {}).values():
                if in_doc:
                    all_docs.append(in_doc)

    return all_docs


class AssumeRolePermResult(tuple):
    """Result tuple supporting (allowed, explicit_deny) unpacking with extended authorization evidence."""
    def __new__(cls, allowed: bool, explicit_deny: bool, is_conditional: bool = False, evidence: Optional[Dict[str, Any]] = None):
        return super().__new__(cls, (allowed, explicit_deny))

    def __init__(self, allowed: bool, explicit_deny: bool, is_conditional: bool = False, evidence: Optional[Dict[str, Any]] = None):
        self.allowed = allowed
        self.explicit_deny = explicit_deny
        self.is_conditional = is_conditional
        self.evidence = evidence or {}


def evaluate_condition_block(
    condition_block: Any,
    principal: Dict[str, Any],
    account_id: str = "",
) -> Dict[str, Any]:
    """Evaluate an IAM Condition block (from trust policy or identity policy) against inventory context.

    Returns:
        {
            "conditions_evaluated": List[str],
            "conditions_satisfied": List[str],
            "conditions_unresolved": List[str],
            "is_violated": bool,         # True if deterministically evaluated to False
            "is_fully_satisfied": bool,  # True iff conditions existed and all were satisfied
        }
    """
    res = {
        "conditions_evaluated": [],
        "conditions_satisfied": [],
        "conditions_unresolved": [],
        "is_violated": False,
        "is_fully_satisfied": False,
    }

    if not condition_block or not isinstance(condition_block, dict):
        res["is_fully_satisfied"] = True
        return res

    caller_arn = str(principal.get("arn") or "").strip().lower()
    caller_account = str(account_id or "").strip().lower()
    if not caller_account and ":" in caller_arn:
        parts = caller_arn.split(":")
        if len(parts) >= 5:
            caller_account = parts[4].lower()

    for operator, expr in condition_block.items():
        if not isinstance(expr, dict):
            res["conditions_unresolved"].append(str(operator))
            continue

        op_lower = str(operator).lower().strip()

        for key, raw_val in expr.items():
            key_str = str(key).strip()
            key_lower = key_str.lower()
            cond_repr = f"{operator}:{key_str}={raw_val}"
            res["conditions_evaluated"].append(cond_repr)

            # Normalize expected values to list of strings
            if isinstance(raw_val, (list, set, tuple)):
                expected_vals = [str(v).strip().lower() for v in raw_val]
            else:
                expected_vals = [str(raw_val).strip().lower()]

            # 1. aws:principalarn
            if key_lower in {"aws:principalarn", "principalarn"}:
                if op_lower in {"stringequals", "arnequals"}:
                    if not caller_arn:
                        res["conditions_unresolved"].append(cond_repr)
                    elif any(caller_arn == ev for ev in expected_vals):
                        res["conditions_satisfied"].append(cond_repr)
                    else:
                        res["is_violated"] = True
                elif op_lower in {"stringlike", "arnlike"}:
                    if not caller_arn:
                        res["conditions_unresolved"].append(cond_repr)
                    elif any(fnmatchcase(caller_arn, ev) for ev in expected_vals):
                        res["conditions_satisfied"].append(cond_repr)
                    else:
                        res["is_violated"] = True
                elif op_lower in {"stringnotequals", "arnnotequals"}:
                    if not caller_arn:
                        res["conditions_unresolved"].append(cond_repr)
                    elif all(caller_arn != ev for ev in expected_vals):
                        res["conditions_satisfied"].append(cond_repr)
                    else:
                        res["is_violated"] = True
                else:
                    res["conditions_unresolved"].append(cond_repr)

            # 2. aws:principalaccount
            elif key_lower in {"aws:principalaccount", "principalaccount"}:
                if op_lower in {"stringequals"}:
                    if not caller_account:
                        res["conditions_unresolved"].append(cond_repr)
                    elif any(caller_account == ev for ev in expected_vals):
                        res["conditions_satisfied"].append(cond_repr)
                    else:
                        res["is_violated"] = True
                elif op_lower in {"stringnotequals"}:
                    if not caller_account:
                        res["conditions_unresolved"].append(cond_repr)
                    elif all(caller_account != ev for ev in expected_vals):
                        res["conditions_satisfied"].append(cond_repr)
                    else:
                        res["is_violated"] = True
                else:
                    res["conditions_unresolved"].append(cond_repr)

            # 3. Runtime/session parameters (MFA, ExternalId, SourceIp, etc.)
            elif key_lower in {
                "aws:multifactorauthpresent",
                "multifactorauthpresent",
                "sts:externalid",
                "externalid",
                "aws:sourceip",
                "sourceip",
            }:
                res["conditions_unresolved"].append(cond_repr)

            # 4. Any other unknown/unsupported condition key or operator
            else:
                res["conditions_unresolved"].append(cond_repr)

    if res["conditions_evaluated"] and not res["is_violated"] and not res["conditions_unresolved"]:
        res["is_fully_satisfied"] = True

    return res


evaluate_trust_statement_condition = evaluate_condition_block


def principal_effective_allows_assume_role(
    principal: Dict[str, Any],
    role_arn: str,
    policy_doc_map: Dict[str, str],
    all_groups: Any = None,
    account_id: str = "",
) -> AssumeRolePermResult:
    """Determine if a principal's effective identity policies grant sts:AssumeRole.

    Evaluates:
    - Direct attached managed + direct inline + group attached + group inline policies.
    - Identity statement Condition blocks (MFA, SourceIp, ExternalId, PrincipalArn, etc.).
    - Permissions boundary (if attached to principal) as limiting policy.
    - Explicit Deny precedence across direct, group, and boundary policies.

    Returns:
        AssumeRolePermResult (subclass of tuple, unpacks as (allowed: bool, explicit_deny: bool)).
        Extended attributes:
            result.is_conditional: bool
            result.evidence: Dict[str, Any]
    """
    docs = get_effective_identity_policy_documents(principal, policy_doc_map, all_groups)
    if not docs:
        return AssumeRolePermResult(
            False, False, is_conditional=False,
            evidence={
                "identity_policy_allow": False,
                "explicit_deny": False,
                "boundary_status": "none",
                "organization_policy_status": "not_collected",
                "conditions_status": "none",
                "authorization_status": "DENIED",
            }
        )

    has_definitive_allow = False
    has_conditional_allow = False
    unresolved_conditions: List[str] = []
    satisfied_conditions: List[str] = []

    for doc in docs:
        stmts = parse_policy_document(doc)
        for stmt in stmts:
            effect = stmt.get("Effect")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])

            if not any(match_action(a, "sts:assumerole") for a in actions):
                continue

            # Check if this statement applies to role_arn
            resource_matches = False
            for r in (resources or ["*"]):
                if r == "*":
                    resource_matches = True
                    break
                if role_arn and fnmatchcase(role_arn.lower(), r.lower()):
                    resource_matches = True
                    break
                if role_arn and r.lower() == role_arn.lower():
                    resource_matches = True
                    break

            if not resource_matches:
                continue

            # Evaluate statement condition if present
            c_eval = evaluate_condition_block(stmt.get("Condition"), principal, account_id)
            if c_eval["is_violated"]:
                continue  # Condition violated, statement does not apply

            if effect == "Deny":
                # Explicit Deny strictly overrides any Allow
                return AssumeRolePermResult(
                    False, True, is_conditional=False,
                    evidence={
                        "identity_policy_allow": False,
                        "explicit_deny": True,
                        "boundary_status": "none",
                        "organization_policy_status": "not_collected",
                        "conditions_status": "satisfied" if c_eval.get("is_fully_satisfied") else "none",
                        "authorization_status": "DENIED",
                    }
                )
            elif effect == "Allow":
                if c_eval.get("conditions_unresolved"):
                    has_conditional_allow = True
                    unresolved_conditions.extend(c_eval["conditions_unresolved"])
                else:
                    has_definitive_allow = True
                    satisfied_conditions.extend(c_eval.get("conditions_satisfied", []))

    # Evaluate Permissions Boundary (if attached to principal)
    boundary_arn = principal.get("permissionsBoundary")
    boundary_status = "none"
    if boundary_arn:
        clean_bname = boundary_arn.split("/")[-1] if "/" in boundary_arn else boundary_arn
        b_doc = policy_doc_map.get(boundary_arn) or policy_doc_map.get(clean_bname)
        if b_doc:
            b_stmts = parse_policy_document(b_doc)
            b_allowed = False
            b_denied = False
            for b_s in b_stmts:
                b_effect = b_s.get("Effect")
                b_actions = b_s.get("Action", [])
                b_resources = b_s.get("Resource", [])
                if any(match_action(a, "sts:assumerole") for a in b_actions):
                    res_match = False
                    for br in (b_resources or ["*"]):
                        if br == "*" or (role_arn and fnmatchcase(role_arn.lower(), br.lower())):
                            res_match = True
                            break
                    if res_match:
                        if b_effect == "Deny":
                            b_denied = True
                            break
                        elif b_effect == "Allow":
                            b_allowed = True
            if b_denied or not b_allowed:
                boundary_status = "restricts_assume_role"
            else:
                boundary_status = "satisfied"
        else:
            boundary_status = "unresolved"

    # Boundary restricts AssumeRole -> Effective Deny
    if boundary_status == "restricts_assume_role":
        return AssumeRolePermResult(
            False, False, is_conditional=False,
            evidence={
                "identity_policy_allow": has_definitive_allow or has_conditional_allow,
                "explicit_deny": False,
                "boundary_status": "restricts_assume_role",
                "organization_policy_status": "not_collected",
                "conditions_status": "none",
                "authorization_status": "DENIED",
            }
        )

    # Boundary document unresolved -> Conditional
    if boundary_status == "unresolved":
        return AssumeRolePermResult(
            False, False, is_conditional=True,
            evidence={
                "identity_policy_allow": has_definitive_allow or has_conditional_allow,
                "explicit_deny": False,
                "boundary_status": "unresolved",
                "organization_policy_status": "not_collected",
                "conditions_status": "conditional",
                "conditions_unresolved": ["permissions_boundary_document_unresolved"],
                "authorization_status": "CONDITIONAL",
            }
        )

    if has_definitive_allow:
        return AssumeRolePermResult(
            True, False, is_conditional=False,
            evidence={
                "identity_policy_allow": True,
                "explicit_deny": False,
                "boundary_status": boundary_status,
                "organization_policy_status": "not_collected",
                "conditions_status": "satisfied" if satisfied_conditions else "none",
                "conditions_satisfied": satisfied_conditions,
                "authorization_status": "DEFINITIVE_ALLOW",
            }
        )

    if has_conditional_allow:
        return AssumeRolePermResult(
            False, False, is_conditional=True,
            evidence={
                "identity_policy_allow": True,
                "explicit_deny": False,
                "boundary_status": boundary_status,
                "organization_policy_status": "not_collected",
                "conditions_status": "conditional",
                "conditions_unresolved": unresolved_conditions,
                "authorization_status": "CONDITIONAL",
            }
        )

    return AssumeRolePermResult(
        False, False, is_conditional=False,
        evidence={
            "identity_policy_allow": False,
            "explicit_deny": False,
            "boundary_status": boundary_status,
            "organization_policy_status": "not_collected",
            "conditions_status": "none",
            "authorization_status": "DENIED",
        }
    )


def _principal_has_assume_role_permission(
    principal: Dict[str, Any],
    role_arn: str,
    policy_doc_map: Dict[str, str],
    all_groups: Any = None,
) -> bool:
    """Wrapper for backward compatibility."""
    res = principal_effective_allows_assume_role(
        principal, role_arn, policy_doc_map, all_groups
    )
    return res[0] and not res[1]


def _principal_has_explicit_deny_on_assume(
    principal: Dict[str, Any],
    role_arn: str,
    policy_doc_map: Dict[str, str],
    all_groups: Any = None,
) -> bool:
    """Wrapper for backward compatibility."""
    res = principal_effective_allows_assume_role(
        principal, role_arn, policy_doc_map, all_groups
    )
    return res[1]


# ─── Authoritative Trust + Call-Permission Evaluator ────────────────────────

def evaluate_assume_role_trust_with_evidence(
    trust_policy_input: Any,
    role_name: str,
    role_arn: str,
    all_users: List[Dict[str, Any]],
    all_roles: List[Dict[str, Any]],
    account_id: str,
    policy_doc_map: Dict[str, str],
    all_groups: Any = None,
) -> Dict[str, Any]:
    """Authoritative AssumeRole evaluator enforcing the 4-layer trust model:

    1. TRUST POLICY: Principal match in trust policy statement.
    2. CALL PERMISSION: Identity policies grant sts:AssumeRole (direct or group-inherited).
       Exact ARN in trust implies call permission; wildcard/root requires identity policy.
    3. NO EXPLICIT DENY: No identity policy or trust policy explicitly Denies sts:AssumeRole.
    4. CONDITIONS PROVEN: All statement conditions must be deterministically satisfied from inventory.
       Unresolved/runtime conditions (MFA, ExternalId, SourceIp) yield CONDITIONAL_TRUST (no CAN_ASSUME edge).

    Returns:
        {
            "users": [
                {
                    "principal": <user dict>,
                    "evidence": {
                        "trust_principal_type": "exact_arn" | "wildcard" | "account_root",
                        "trust_status": "definitive" | "conditional",
                        "trust_conditional": bool,
                        "authorization_status": "DEFINITIVE_ALLOW" | "CONDITIONAL" | "DENIED" | "UNSUPPORTED",
                        "identity_policy_allow": bool,
                        "explicit_deny": bool,
                        "boundary_status": "none" | "satisfied" | "restricts_assume_role" | "unresolved",
                        "organization_policy_status": "not_collected",
                        "conditions_status": "satisfied" | "conditional" | "violated" | "none",
                        "conditions_evaluated": List[str],
                        "conditions_satisfied": List[str],
                        "conditions_unresolved": List[str],
                        "call_permission_verified": bool,
                    }
                },
                ...
            ],
            "roles": [ ... same structure ... ],
            "conditional_trusts": [ ... entries with trust_status == 'conditional' ... ],
            "trust_is_broad": bool,
            "trust_principal_types": set(),
        }
    """
    result: Dict[str, Any] = {
        "users": [],
        "roles": [],
        "conditional_trusts": [],
        "trust_is_broad": False,
        "trust_principal_types": set(),
    }

    statements = parse_policy_document(trust_policy_input)
    if not statements:
        return result

    user_name_map = {u["name"]: u for u in all_users}
    user_arn_map = {u["arn"]: u for u in all_users if u.get("arn")}
    role_name_map = {r["name"]: r for r in all_roles if r["name"] != role_name}
    role_arn_map = {r["arn"]: r for r in all_roles if r["name"] != role_name and r.get("arn")}

    added_user_ids: Dict[str, Dict[str, Any]] = {}
    added_role_names: Dict[str, Dict[str, Any]] = {}

    # Pre-check for trust-policy level explicit Deny statements
    trust_explicit_denies: List[Dict[str, Any]] = [
        s for s in statements if s.get("Effect") == "Deny"
        and any(match_action(a, "sts:assumerole") for a in s.get("Action", []))
    ]

    def _is_denied_by_trust_policy(caller: Dict[str, Any]) -> bool:
        """Check if any Effect: Deny in the trust policy matches this caller."""
        caller_arn = str(caller.get("arn") or "").lower()
        caller_name = str(caller.get("name") or "").lower()
        for dstmt in trust_explicit_denies:
            d_princ = dstmt.get("Principal", {})
            d_cond = dstmt.get("Condition", {})
            if d_cond:
                c_eval = evaluate_condition_block(d_cond, caller, account_id)
                if c_eval["is_violated"]:
                    continue  # Condition violated, Deny does not apply

            if d_princ == "*":
                return True
            if isinstance(d_princ, dict):
                p_aws = d_princ.get("AWS", [])
                if isinstance(p_aws, str):
                    p_aws = [p_aws]
                for p_str in p_aws:
                    p_s = str(p_str).strip().lower()
                    if p_s == "*" or p_s == caller_arn or p_s.endswith(f"/{caller_name}"):
                        return True
        return False

    def _process_user(u_obj: Dict[str, Any], trust_type: str, cond_eval: Dict[str, Any], requires_call_perm_check: bool):
        uid = u_obj.get("id") or u_obj.get("name")

        # 1. Check trust-policy explicit deny
        if _is_denied_by_trust_policy(u_obj):
            return

        # 2. Check identity-policy permissions, conditions, and boundary
        perm_res = principal_effective_allows_assume_role(
            u_obj, role_arn, policy_doc_map, all_groups, account_id=account_id
        )
        call_perm = perm_res.allowed
        explicit_deny = perm_res.explicit_deny
        is_conditional_perm = perm_res.is_conditional
        perm_ev = perm_res.evidence

        if explicit_deny:
            return
        if perm_ev.get("boundary_status") == "restricts_assume_role":
            return

        if requires_call_perm_check and not call_perm and not is_conditional_perm:
            return

        # 3. Check trust condition resolution & identity condition resolution
        all_unresolved = cond_eval.get("conditions_unresolved", []) + perm_ev.get("conditions_unresolved", [])
        all_evaluated = cond_eval.get("conditions_evaluated", []) + perm_ev.get("conditions_unresolved", [])
        all_satisfied = cond_eval.get("conditions_satisfied", []) + perm_ev.get("conditions_satisfied", [])
        boundary_unresolved = perm_ev.get("boundary_status") == "unresolved"

        has_unresolved = len(all_unresolved) > 0 or is_conditional_perm or boundary_unresolved
        trust_status = "conditional" if has_unresolved else "definitive"
        trust_conditional = bool(all_evaluated)
        auth_status = "CONDITIONAL" if has_unresolved else "DEFINITIVE_ALLOW"
        call_verified = (call_perm if requires_call_perm_check else True) and not has_unresolved

        entry = {
            "principal": u_obj,
            "evidence": {
                "trust_principal_type": trust_type,
                "trust_status": trust_status,
                "trust_conditional": trust_conditional,
                "authorization_status": auth_status,
                "identity_policy_allow": call_perm or is_conditional_perm or (trust_type == "exact_arn"),
                "explicit_deny": False,
                "boundary_status": perm_ev.get("boundary_status", "none"),
                "organization_policy_status": "not_collected",
                "conditions_status": "conditional" if (all_unresolved or boundary_unresolved) else ("satisfied" if all_satisfied else "none"),
                "conditions_evaluated": all_evaluated,
                "conditions_satisfied": all_satisfied,
                "conditions_unresolved": all_unresolved,
                "call_permission_verified": call_verified,
            },
        }

        # Handle promotion from conditional to definitive if multiple statements apply
        if uid in added_user_ids:
            existing = added_user_ids[uid]
            if existing["evidence"]["trust_status"] == "conditional" and trust_status == "definitive":
                existing["evidence"].update(entry["evidence"])
                if existing in result["conditional_trusts"]:
                    result["conditional_trusts"].remove(existing)
            return

        result["users"].append(entry)
        if trust_status == "conditional":
            result["conditional_trusts"].append(entry)
        added_user_ids[uid] = entry

    def _process_role(r_obj: Dict[str, Any], trust_type: str, cond_eval: Dict[str, Any], requires_call_perm_check: bool):
        rn = r_obj["name"]

        if _is_denied_by_trust_policy(r_obj):
            return

        perm_res = principal_effective_allows_assume_role(
            r_obj, role_arn, policy_doc_map, all_groups, account_id=account_id
        )
        call_perm = perm_res.allowed
        explicit_deny = perm_res.explicit_deny
        is_conditional_perm = perm_res.is_conditional
        perm_ev = perm_res.evidence

        if explicit_deny:
            return
        if perm_ev.get("boundary_status") == "restricts_assume_role":
            return

        if requires_call_perm_check and not call_perm and not is_conditional_perm:
            return

        all_unresolved = cond_eval.get("conditions_unresolved", []) + perm_ev.get("conditions_unresolved", [])
        all_evaluated = cond_eval.get("conditions_evaluated", []) + perm_ev.get("conditions_unresolved", [])
        all_satisfied = cond_eval.get("conditions_satisfied", []) + perm_ev.get("conditions_satisfied", [])
        boundary_unresolved = perm_ev.get("boundary_status") == "unresolved"

        has_unresolved = len(all_unresolved) > 0 or is_conditional_perm or boundary_unresolved
        trust_status = "conditional" if has_unresolved else "definitive"
        trust_conditional = bool(all_evaluated)
        auth_status = "CONDITIONAL" if has_unresolved else "DEFINITIVE_ALLOW"
        call_verified = (call_perm if requires_call_perm_check else True) and not has_unresolved

        entry = {
            "principal": r_obj,
            "evidence": {
                "trust_principal_type": trust_type,
                "trust_status": trust_status,
                "trust_conditional": trust_conditional,
                "authorization_status": auth_status,
                "identity_policy_allow": call_perm or is_conditional_perm or (trust_type == "exact_arn"),
                "explicit_deny": False,
                "boundary_status": perm_ev.get("boundary_status", "none"),
                "organization_policy_status": "not_collected",
                "conditions_status": "conditional" if (all_unresolved or boundary_unresolved) else ("satisfied" if all_satisfied else "none"),
                "conditions_evaluated": all_evaluated,
                "conditions_satisfied": all_satisfied,
                "conditions_unresolved": all_unresolved,
                "call_permission_verified": call_verified,
            },
        }

        if rn in added_role_names:
            existing = added_role_names[rn]
            if existing["evidence"]["trust_status"] == "conditional" and trust_status == "definitive":
                existing["evidence"].update(entry["evidence"])
                if existing in result["conditional_trusts"]:
                    result["conditional_trusts"].remove(existing)
            return

        result["roles"].append(entry)
        if trust_status == "conditional":
            result["conditional_trusts"].append(entry)
        added_role_names[rn] = entry

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = [a.lower() for a in stmt.get("Action", [])]
        if not any(match_action(a, "sts:assumerole") for a in actions):
            continue

        principal = stmt.get("Principal", {})
        if not principal:
            continue

        stmt_condition = stmt.get("Condition")

        # ── Wildcard principal ("*" at top level or AWS: "*") ────────────────
        is_wildcard = (
            principal == "*"
            or (isinstance(principal, dict) and principal.get("AWS") == "*")
        )
        if is_wildcard:
            result["trust_is_broad"] = True
            result["trust_principal_types"].add("wildcard")
            for u in all_users:
                c_eval = evaluate_trust_statement_condition(stmt_condition, u, account_id)
                if not c_eval["is_violated"]:
                    _process_user(u, "wildcard", c_eval, requires_call_perm_check=True)
            for r in all_roles:
                if r["name"] == role_name:
                    continue
                c_eval = evaluate_trust_statement_condition(stmt_condition, r, account_id)
                if not c_eval["is_violated"]:
                    _process_role(r, "wildcard", c_eval, requires_call_perm_check=True)
            continue

        aws_principals = principal.get("AWS", []) if isinstance(principal, dict) else []
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        elif not isinstance(aws_principals, list):
            aws_principals = []

        for p_str in aws_principals:
            p = str(p_str).strip()

            # ── Per-entry wildcard ────────────────────────────────────────────
            if p == "*":
                result["trust_is_broad"] = True
                result["trust_principal_types"].add("wildcard")
                for u in all_users:
                    c_eval = evaluate_trust_statement_condition(stmt_condition, u, account_id)
                    if not c_eval["is_violated"]:
                        _process_user(u, "wildcard", c_eval, requires_call_perm_check=True)
                for r in all_roles:
                    if r["name"] == role_name:
                        continue
                    c_eval = evaluate_trust_statement_condition(stmt_condition, r, account_id)
                    if not c_eval["is_violated"]:
                        _process_role(r, "wildcard", c_eval, requires_call_perm_check=True)
                continue

            # ── Account root ARN or bare account ID ──────────────────────────
            if p.endswith(":root") or (account_id and p == account_id):
                result["trust_is_broad"] = True
                result["trust_principal_types"].add("account_root")
                for u in all_users:
                    c_eval = evaluate_trust_statement_condition(stmt_condition, u, account_id)
                    if not c_eval["is_violated"]:
                        _process_user(u, "account_root", c_eval, requires_call_perm_check=True)
                for r in all_roles:
                    if r["name"] == role_name:
                        continue
                    c_eval = evaluate_trust_statement_condition(stmt_condition, r, account_id)
                    if not c_eval["is_violated"]:
                        _process_role(r, "account_root", c_eval, requires_call_perm_check=True)
                continue

            # ── Specific Role ARN ─────────────────────────────────────────────
            if ":role/" in p:
                r_name = p.split("/")[-1]
                r_obj = role_name_map.get(r_name) or role_arn_map.get(p)
                if r_obj:
                    c_eval = evaluate_trust_statement_condition(stmt_condition, r_obj, account_id)
                    if not c_eval["is_violated"]:
                        result["trust_principal_types"].add("exact_arn")
                        _process_role(r_obj, "exact_arn", c_eval, requires_call_perm_check=False)
                continue

            # ── Specific User ARN ─────────────────────────────────────────────
            if ":user/" in p:
                u_name = p.split("/")[-1]
                u_obj = user_name_map.get(u_name) or user_arn_map.get(p)
                if u_obj:
                    c_eval = evaluate_trust_statement_condition(stmt_condition, u_obj, account_id)
                    if not c_eval["is_violated"]:
                        result["trust_principal_types"].add("exact_arn")
                        _process_user(u_obj, "exact_arn", c_eval, requires_call_perm_check=False)
                continue

    return result

