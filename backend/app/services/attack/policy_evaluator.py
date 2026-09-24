"""
IAM Policy, Trust Policy, and Resource ARN Evaluator.

Parses actual IAM Policy JSON documents and AssumeRole trust policies to
determine concrete permissions, access relationships, and risk factors
WITHOUT relying on heuristic policy/role/resource name matching.
"""

import json
import logging
import re
from enum import Enum
from fnmatch import fnmatchcase
from typing import Any, Dict, List, Set, Tuple, Optional
from app.services.risk.risk_constants import (
    WEIGHTS,
    DANGEROUS_ESCALATION_ACTIONS,
    BROAD_ADMIN_ACTIONS
)

logger = logging.getLogger("scanner")


class PolicyDecision(str, Enum):
    """Explicit IAM evaluation decision states."""
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    CONDITIONAL = "CONDITIONAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


DECISION_ALLOWED = PolicyDecision.ALLOWED.value
DECISION_DENIED = PolicyDecision.DENIED.value
DECISION_CONDITIONAL = PolicyDecision.CONDITIONAL.value
DECISION_NOT_APPLICABLE = PolicyDecision.NOT_APPLICABLE.value

RDS_MANAGEMENT_ACTIONS = {
    "rds:describedbinstances",
    "rds:describedbclusters",
    "rds:modifydbinstance",
    "rds:modifydbcluster",
    "rds:createdbinstance",
    "rds:createdbcluster",
    "rds:deletedbinstance",
    "rds:deletedbcluster",
    "rds:startdbcluster",
    "rds:stopdbcluster",
    "rds:rebootdbinstance",
}

RDS_DB_CONNECT_ACTION = "rds-db:connect"


class PolicyEvaluator:
    """Wrapper class providing policy evaluation helpers."""
    pass


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
            "Sid": stmt.get("Sid") or stmt.get("sid", ""),
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


def match_statement_action(actions: List[str], not_actions: List[str], target_action: str) -> bool:
    """Check if an IAM statement's Action / NotAction matches target_action.

    - If Action is specified: True if ANY pattern in Action matches target_action.
    - If NotAction is specified: True if NO pattern in NotAction matches target_action.
    - If neither is specified: False.
    """
    if actions:
        return any(match_action(a, target_action) for a in actions)
    if not_actions:
        return not any(match_action(na, target_action) for na in not_actions)
    return False


def has_service_action(stmt_actions: List[str], not_actions: List[str], service_prefix: str) -> bool:
    """Check if actions grant access to the specified AWS service (taking NotAction into account)."""
    service = service_prefix.lower().rstrip(":")

    # If NotAction is used
    if not_actions:
        if any(na.lower().strip() in (f"{service}:*", "*", "*:*") for na in not_actions):
            return False
        return True

    for action in stmt_actions:
        a = action.lower().strip()
        if a in ("*", "*:*"):
            return True
        if a.startswith(f"{service}:") or fnmatchcase(f"{service}:action", a):
            return True
    return False


def match_resource_specific_action(action: str, res_type: str) -> bool:
    """Check if an action specifically grants access to the given cloud resource type.
    
    Prevents false-positive access where an account-level or infrastructure-level action
    (e.g. ec2:DescribeSecurityGroups or s3:ListAllMyBuckets) is incorrectly attributed
    as direct access to a specific resource instance.
    """
    a = action.lower().strip()
    if a in ("*", "*:*"):
        return True

    t = res_type.upper()
    if t == "S3":
        if a in ("s3:*", "s3:*object*", "s3:*bucket*"):
            return True
        if a.startswith("s3:"):
            account_only = {"s3:listallmybuckets", "s3:getaccountpublicaccessblock", "s3:putaccountpublicaccessblock"}
            if a in account_only:
                return False
            return True
        return False

    elif t == "EC2":
        if a in ("ec2:*", "ec2:*instance*"):
            return True
        if a.startswith("ec2-instance-connect:"):
            return True
        if a.startswith("ec2:"):
            non_instance_prefixes = (
                "ec2:describesecuritygroups",
                "ec2:describesubnets",
                "ec2:describevpcs",
                "ec2:describeroutetables",
                "ec2:describeinternetgateways",
                "ec2:describenetworkacls",
                "ec2:describekeypairs",
                "ec2:describevpcendpoints",
                "ec2:getsecuritygroupsforvpc",
                "ec2:describeflowlogs",
                "ec2:describenatgateways",
                "ec2:describeavailabilityzones",
                "ec2:describeregions",
                "ec2:describevpngateways",
                "ec2:describecustomergateways",
                "ec2:describevpnconnections",
            )
            if any(a.startswith(p) for p in non_instance_prefixes):
                return False
            return True
        return False

    elif t == "LAMBDA":
        if a in ("lambda:*", "lambda:*function*"):
            return True
        if a.startswith("lambda:"):
            non_function = {"lambda:listfunctions", "lambda:listeventsourcemappings", "lambda:listlayers", "lambda:listlayerversions"}
            if a in non_function:
                return False
            return True
        return False

    elif t in ("SECRETS", "SECRET"):
        if a in ("secretsmanager:*", "secretsmanager:*secret*"):
            return True
        if a.startswith("secretsmanager:"):
            non_secret = {"secretsmanager:listsecrets", "secretsmanager:getrandompassword"}
            if a in non_secret:
                return False
            return True
        return False

    elif t == "RDS":
        if a in ("rds:*", "rds-db:*", "rds:*instance*", "rds:*cluster*"):
            return True
        if a.startswith("rds-db:connect"):
            return True
        if a.startswith("rds:"):
            non_db = {"rds:describeevents", "rds:describeeventsubscriptions", "rds:describedbparametergroups", "rds:describedbsubnetgroups"}
            if a in non_db:
                return False
            return True
        return False

    elif t == "DYNAMODB":
        if a in ("dynamodb:*", "dynamodb:*table*", "dynamodb:*item*"):
            return True
        if a.startswith("dynamodb:"):
            if a in ("dynamodb:listtables", "dynamodb:listbackups", "dynamodb:liststreams"):
                return False
            return True
        return False

    return False


def find_statement_matched_action(
    actions: List[str],
    not_actions: List[str],
    res_type: str,
    service_prefix: str
) -> Optional[str]:
    """Find the specific action that matches the resource type, or None if no match."""
    if not_actions:
        if any(na.lower().strip() in (f"{service_prefix}:*", "*", "*:*") for na in not_actions):
            return None
        return f"{service_prefix}:*"

    for action in actions:
        if match_resource_specific_action(action, res_type):
            return action
    return None


def classify_resource_relationship(res_type: str, action: str) -> str:
    """Classify the semantic relationship label for access to a given resource type."""
    t = res_type.upper()
    act = action.lower().strip()
    if t == "LAMBDA":
        if "invoke" in act or act in ("lambda:*", "*", "*:*"):
            return "CAN_INVOKE"
        return "CAN_MANAGE"
    if t == "RDS" and "connect" in act:
        return "DB_CONNECT"
    return "ALLOWS"



def _matches_single_resource_pattern(pattern: str, target_res: Any) -> bool:
    """Match a single pattern string against an inventory resource object or ARN string."""
    p_clean = pattern.strip()
    if not p_clean or p_clean == "*":
        return True

    if isinstance(target_res, str):
        res_arn = target_res.strip()
        res_name = res_arn.split(":")[-1].split("/")[-1]
        res_type = ""
        res_id = res_name
    elif isinstance(target_res, dict):
        res_arn = target_res.get("arn", "").strip()
        res_name = target_res.get("name", "").strip()
        res_type = target_res.get("type", "").strip()
        res_id = target_res.get("id", "").strip()
    else:
        return False

    p_clean_lower = p_clean.lower()
    res_arn_lower = res_arn.lower()

    # Exact or glob pattern match on full ARN
    if res_arn and fnmatchcase(res_arn_lower, p_clean_lower):
        return True

    # S3 specific matching: arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/*
    if res_type == "S3" or res_arn_lower.startswith("arn:aws:s3:::"):
        clean_pattern = p_clean.rstrip("/*").rstrip("/")
        if res_arn and fnmatchcase(res_arn_lower, clean_pattern.lower()):
            return True
        if res_name:
            if clean_pattern.lower() == f"arn:aws:s3:::{res_name}".lower():
                return True
            if fnmatchcase(f"arn:aws:s3:::{res_name}".lower(), clean_pattern.lower()):
                return True

    # Aurora / RDS IAM DB User specific matching: arn:aws:rds-db:<region>:<account>:dbuser:<db-id>/<username>
    if "arn:aws:rds-db:" in res_arn_lower or "arn:aws:rds-db:" in p_clean_lower:
        if res_arn and fnmatchcase(res_arn_lower, p_clean_lower):
            return True
        return False

    # Secrets Manager specific matching: arn contains secret name prefix
    if res_type in ("Secrets", "Secret") or ":secretsmanager:" in res_arn_lower:
        if p_clean.endswith("*"):
            prefix = p_clean.rstrip("*")
            if res_arn and res_arn_lower.startswith(prefix.lower()):
                return True
        if res_name and f":secret:{res_name.lower()}" in p_clean_lower:
            return True

    # DynamoDB specific matching: arn:aws:dynamodb:...:table/TableName
    if res_type == "DynamoDB" or ":dynamodb:" in res_arn_lower:
        if res_name and f":table/{res_name.lower()}" in p_clean_lower:
            return True

    # RDS specific matching: arn:aws:rds:...:db:DbInstanceIdentifier or :cluster:DbClusterIdentifier
    if res_type == "RDS" or (":rds:" in res_arn_lower and "arn:aws:rds-db:" not in res_arn_lower):
        if res_name and (f":db:{res_name.lower()}" in p_clean_lower or f":cluster:{res_name.lower()}" in p_clean_lower):
            return True

    # EC2 specific matching: arn:aws:ec2:...:instance/i-xxx
    if res_type == "EC2" or ":ec2:" in res_arn_lower:
        if res_name and f":instance/{res_name.lower()}" in p_clean_lower:
            return True
        if res_id and f":instance/{res_id.lower()}" in p_clean_lower:
            return True

    # Lambda specific matching: arn:aws:lambda:...:function:FuncName
    if res_type == "Lambda" or ":lambda:" in res_arn_lower:
        if res_name and (f":function:{res_name.lower()}" in p_clean_lower or f":function/{res_name.lower()}" in p_clean_lower):
            return True
        if res_id and (f":function:{res_id.lower()}" in p_clean_lower or f":function/{res_id.lower()}" in p_clean_lower):
            return True

    return False


def match_resource_arn(resource_pattern: str, not_resources: List[str], target_res: Any) -> bool:
    """Match a policy resource ARN pattern against an inventory resource object or ARN.

    If not_resources is specified, returns False if target_res matches ANY not_resources pattern.
    """
    if not_resources:
        for nr in not_resources:
            if _matches_single_resource_pattern(nr, target_res):
                return False

    if not resource_pattern:
        return True

    return _matches_single_resource_pattern(resource_pattern, target_res)


def match_statement_resource(resources: List[str], not_resources: List[str], target_res: Any) -> bool:
    """Check if an IAM statement's Resource / NotResource matches target_res.

    If not_resources is specified and target_res matches ANY pattern in not_resources -> False.
    If resources is specified, returns True if target_res matches ANY pattern in resources.
    If resources is empty/not specified, default is ["*"] -> True.
    """
    if not_resources:
        for nr in not_resources:
            if _matches_single_resource_pattern(nr, target_res):
                return False

    res_patterns = resources or ["*"]
    return any(_matches_single_resource_pattern(rp, target_res) for rp in res_patterns)


def match_principal(statement_principal: Any, target_principal: Any, account_id: str = "") -> bool:
    """Check if an IAM statement's Principal matches target_principal.

    target_principal can be:
      - dict with keys 'arn', 'name', 'type'
      - or an ARN string (e.g. 'arn:aws:iam::123456789012:user/alice')
    """
    if not statement_principal:
        return False

    if isinstance(target_principal, str):
        target_arn = target_principal.strip().lower()
        target_name = target_arn.split("/")[-1]
    elif isinstance(target_principal, dict):
        target_arn = str(target_principal.get("arn") or "").strip().lower()
        target_name = str(target_principal.get("name") or "").strip().lower()
    else:
        return False

    # Wildcard principal: "*" or {"AWS": "*"}
    if statement_principal == "*":
        return True

    if isinstance(statement_principal, dict):
        if statement_principal.get("AWS") == "*":
            return True

        aws_p = statement_principal.get("AWS", [])
        if isinstance(aws_p, str):
            aws_p = [aws_p]
        elif not isinstance(aws_p, list):
            aws_p = []

        for p_val in aws_p:
            p_str = str(p_val).strip().lower()
            if p_str == "*":
                return True
            if target_arn and p_str == target_arn:
                return True
            if target_arn and fnmatchcase(target_arn, p_str):
                return True
            if target_name and p_str.endswith(f"/{target_name}"):
                return True
            if p_str.endswith(":root"):
                root_account = p_str.split(":")[4] if len(p_str.split(":")) >= 5 else ""
                target_account = target_arn.split(":")[4] if len(target_arn.split(":")) >= 5 else account_id
                if root_account and root_account == target_account:
                    return True
            elif account_id and p_str == account_id.lower():
                return True

        # Service Principal check (e.g. {"Service": "ec2.amazonaws.com"})
        srv_p = statement_principal.get("Service", [])
        if isinstance(srv_p, str):
            srv_p = [srv_p]
        elif not isinstance(srv_p, list):
            srv_p = []
        for s_val in srv_p:
            s_str = str(s_val).strip().lower()
            if s_str == "*":
                return True
            if target_arn and (s_str == target_arn or fnmatchcase(target_arn, s_str)):
                return True

    return False


def _build_evidence(
    principal: Optional[Dict[str, Any]],
    policy_name: str,
    policy_arn: str,
    stmt: Dict[str, Any],
    target_action: str,
    target_resource: Any,
    decision: PolicyDecision,
    reason: str,
    condition_status: str = "none",
    cond_eval: Optional[Dict[str, Any]] = None,
    source: str = "direct_policy",
) -> Dict[str, Any]:
    """Construct a structured, explainable authorization evidence object."""
    p_name = ""
    p_type = "User"
    if principal:
        p_name = principal.get("name") or principal.get("username") or principal.get("id") or ""
        p_type = principal.get("type", "User")

    res_arn = ""
    res_region = ""
    if isinstance(target_resource, dict):
        res_arn = target_resource.get("arn", "")
        res_region = target_resource.get("region", "")
    elif isinstance(target_resource, str):
        res_arn = target_resource
        parts = target_resource.split(":")
        if len(parts) >= 4:
            res_region = parts[3]

    ce = cond_eval or {}

    return {
        "principal": p_name,
        "principal_type": p_type,
        "policy_arn": policy_arn,
        "policy_name": policy_name,
        "statement_sid": stmt.get("Sid") or stmt.get("sid") or "",
        "effect": stmt.get("Effect", "Deny"),
        "action": stmt.get("Action", []),
        "not_action": stmt.get("NotAction", []),
        "resource": stmt.get("Resource", []),
        "not_resource": stmt.get("NotResource", []),
        "matched_action": target_action,
        "matched_resource": res_arn or (target_resource.get("id", "") if isinstance(target_resource, dict) else ""),
        "condition_status": condition_status,
        "conditions_evaluated": ce.get("conditions_evaluated", []),
        "conditions_satisfied": ce.get("conditions_satisfied", []),
        "conditions_unresolved": ce.get("conditions_unresolved", []),
        "decision": decision.value,
        "source": source,
        "region": res_region,
        "resource_arn": res_arn,
        "reason": reason,
    }


def evaluate_statement(
    stmt: Dict[str, Any],
    target_action: str,
    target_resource: Any,
    principal: Optional[Dict[str, Any]] = None,
    account_id: str = "",
    policy_name: str = "",
    policy_arn: str = "",
    source: str = "direct_policy",
) -> Tuple[PolicyDecision, Dict[str, Any]]:
    """Authoritative single IAM statement evaluator.

    Evaluates:
      - Action / NotAction
      - Resource / NotResource
      - Principal (if present in resource/trust policy)
      - Condition block (satisfiable vs unresolved vs violated)
      - Effect (Allow vs Deny)

    Returns:
      (PolicyDecision, evidence_dict)
    """
    effect = stmt.get("Effect", "Deny")
    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    not_actions = stmt.get("NotAction", [])
    if isinstance(not_actions, str):
        not_actions = [not_actions]
    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    not_resources = stmt.get("NotResource", [])
    if isinstance(not_resources, str):
        not_resources = [not_resources]
    stmt_principal = stmt.get("Principal")

    # 1. Action / NotAction matching
    if not match_statement_action(actions, not_actions, target_action):
        ev = _build_evidence(
            principal, policy_name, policy_arn, stmt, target_action, target_resource,
            PolicyDecision.NOT_APPLICABLE,
            f"Action '{target_action}' does not match statement Action/NotAction",
            condition_status="none", source=source
        )
        return PolicyDecision.NOT_APPLICABLE, ev

    # 2. Resource / NotResource matching
    if not match_statement_resource(resources, not_resources, target_resource):
        res_repr = target_resource.get("arn") if isinstance(target_resource, dict) else str(target_resource)
        ev = _build_evidence(
            principal, policy_name, policy_arn, stmt, target_action, target_resource,
            PolicyDecision.NOT_APPLICABLE,
            f"Resource '{res_repr}' does not match statement Resource/NotResource",
            condition_status="none", source=source
        )
        return PolicyDecision.NOT_APPLICABLE, ev

    # 3. Principal matching (if statement defines a Principal)
    if stmt_principal:
        if not match_principal(stmt_principal, principal or {}, account_id):
            p_repr = principal.get("arn") if principal else "unspecified"
            ev = _build_evidence(
                principal, policy_name, policy_arn, stmt, target_action, target_resource,
                PolicyDecision.NOT_APPLICABLE,
                f"Principal '{p_repr}' does not match statement Principal",
                condition_status="none", source=source
            )
            return PolicyDecision.NOT_APPLICABLE, ev

    # 4. Condition evaluation
    cond = stmt.get("Condition")
    cond_status = "none"
    c_eval: Dict[str, Any] = {}
    if cond:
        c_eval = evaluate_condition_block(cond, principal or {}, account_id)
        if c_eval["is_violated"]:
            ev = _build_evidence(
                principal, policy_name, policy_arn, stmt, target_action, target_resource,
                PolicyDecision.NOT_APPLICABLE,
                f"Statement condition deterministically violated: {c_eval.get('conditions_evaluated', [])}",
                condition_status="violated", cond_eval=c_eval, source=source
            )
            return PolicyDecision.NOT_APPLICABLE, ev

        if c_eval["conditions_unresolved"]:
            ev = _build_evidence(
                principal, policy_name, policy_arn, stmt, target_action, target_resource,
                PolicyDecision.CONDITIONAL,
                f"Condition requires unavailable runtime context: {', '.join(c_eval['conditions_unresolved'])}",
                condition_status="unresolved", cond_eval=c_eval, source=source
            )
            return PolicyDecision.CONDITIONAL, ev

        if c_eval.get("is_fully_satisfied"):
            cond_status = "satisfied"

    # 5. Effect evaluation
    if effect == "Deny":
        ev = _build_evidence(
            principal, policy_name, policy_arn, stmt, target_action, target_resource,
            PolicyDecision.DENIED,
            "Explicit Deny statement matched",
            condition_status=cond_status, cond_eval=c_eval, source=source
        )
        return PolicyDecision.DENIED, ev

    ev = _build_evidence(
        principal, policy_name, policy_arn, stmt, target_action, target_resource,
        PolicyDecision.ALLOWED,
        "Allow statement matched",
        condition_status=cond_status, cond_eval=c_eval, source=source
    )
    return PolicyDecision.ALLOWED, ev


def evaluate_authorization_decision(
    policy_docs: List[Any],
    target_action: str,
    target_resource: Any,
    principal: Optional[Dict[str, Any]] = None,
    account_id: str = "",
    policy_names: Optional[List[str]] = None,
    policy_arns: Optional[List[str]] = None,
    source: str = "direct_policy",
) -> Tuple[PolicyDecision, Dict[str, Any]]:
    """Authoritative multi-policy evaluation adhering to AWS evaluation logic:

    1. EXPLICIT DENY: Any matching Deny statement with satisfied conditions immediately returns DENIED.
    2. ALLOW: If at least one matching Allow statement is satisfied and no Deny matches -> ALLOWED.
    3. CONDITIONAL: If an Allow or Deny matches but conditions cannot be proven from scanner context -> CONDITIONAL.
    4. DEFAULT DENY: If no Allow statement matches -> DENIED (implicit deny).
    """
    has_allow = False
    has_conditional = False
    allow_ev: Optional[Dict[str, Any]] = None
    conditional_ev: Optional[Dict[str, Any]] = None

    p_names = policy_names or []
    p_arns = policy_arns or []

    for idx, doc in enumerate(policy_docs):
        pol_name = p_names[idx] if idx < len(p_names) else f"Policy_{idx+1}"
        pol_arn = p_arns[idx] if idx < len(p_arns) else ""
        stmts = parse_policy_document(doc)

        for stmt in stmts:
            dec, ev = evaluate_statement(
                stmt=stmt,
                target_action=target_action,
                target_resource=target_resource,
                principal=principal,
                account_id=account_id,
                policy_name=pol_name,
                policy_arn=pol_arn,
                source=source,
            )

            if dec == PolicyDecision.DENIED:
                # Explicit Deny wins immediately across all statements and policies!
                return PolicyDecision.DENIED, ev

            if dec == PolicyDecision.ALLOWED:
                has_allow = True
                if allow_ev is None:
                    allow_ev = ev

            elif dec == PolicyDecision.CONDITIONAL:
                has_conditional = True
                if conditional_ev is None:
                    conditional_ev = ev

    if has_allow:
        return PolicyDecision.ALLOWED, (allow_ev or {})

    if has_conditional:
        return PolicyDecision.CONDITIONAL, (conditional_ev or {})

    default_deny_ev = _build_evidence(
        principal=principal,
        policy_name=p_names[0] if p_names else "ImplicitDeny",
        policy_arn=p_arns[0] if p_arns else "",
        stmt={"Effect": "Deny", "Action": [], "Resource": []},
        target_action=target_action,
        target_resource=target_resource,
        decision=PolicyDecision.DENIED,
        reason="No matching Allow statement found (default implicit deny)",
        condition_status="none",
        source=source,
    )
    return PolicyDecision.DENIED, default_deny_ev


def evaluate_rds_db_connect(
    policy_doc_input: Any,
    db_resource_id: str,
    db_username: str,
    principal: Optional[Dict[str, Any]] = None,
    account_id: str = "",
    region: str = "us-east-1",
    policy_name: str = "",
    policy_arn: str = "",
) -> Tuple[PolicyDecision, Dict[str, Any]]:
    """Evaluate whether an IAM policy grants database authentication via rds-db:connect.

    Resource ARN format for RDS/Aurora IAM database authentication:
        arn:aws:rds-db:<region>:<account-id>:dbuser:<db-cluster-resource-id-or-dbi-resource-id>/<db-username>

    Rules:
    - Normal RDS management permissions (rds:Describe*, rds:Modify*, etc.) NEVER grant DB connect.
    - An incorrect DB user ARN does not match.
    - Explicit Deny overrides rds-db:connect.
    - Unresolved conditions remain CONDITIONAL.
    - Returns (decision, evidence).
    """
    target_arn = f"arn:aws:rds-db:{region}:{account_id}:dbuser:{db_resource_id}/{db_username}"
    target_res = {
        "id": f"{db_resource_id}/{db_username}",
        "name": f"{db_resource_id}/{db_username}",
        "arn": target_arn,
        "type": "RDS_DB_USER",
        "region": region,
    }

    docs = policy_doc_input if isinstance(policy_doc_input, list) else [policy_doc_input]
    p_names = [policy_name] if policy_name else ["Policy"]
    p_arns = [policy_arn] if policy_arn else [""]

    dec, ev = evaluate_authorization_decision(
        policy_docs=docs,
        target_action="rds-db:connect",
        target_resource=target_res,
        principal=principal,
        account_id=account_id,
        policy_names=p_names,
        policy_arns=p_arns,
        source="database_authentication",
    )

    ev["db_resource_id"] = db_resource_id
    ev["db_username"] = db_username
    return dec, ev


def evaluate_policy_allows_resources(
    policy_doc_input: Any,
    inventory_resources: List[Dict[str, Any]],
    principal: Optional[Dict[str, Any]] = None,
    account_id: str = "",
) -> List[Dict[str, Any]]:
    """Determine which specific inventory resources a policy document grants access to.

    Evaluates Effect: Allow statements against each resource in the inventory,
    evaluates statement Conditions, and ensures explicit DENY statements properly override any ALLOW.
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

            # Check if this statement applies to this resource's service & resource-specific actions
            matched_act = find_statement_matched_action(actions, not_actions, res_type, service_prefix)
            if not matched_act:
                continue

            # Check if this statement applies to this resource's ARN
            resource_matches = False
            for res_pattern in (resources or ["*"]):
                if match_resource_arn(res_pattern, not_resources, res):
                    resource_matches = True
                    break

            if resource_matches:
                # Evaluate Condition block
                cond = stmt.get("Condition")
                if cond:
                    c_eval = evaluate_condition_block(cond, principal or {}, account_id)
                    # If condition deterministically violated, statement does NOT apply
                    if c_eval["is_violated"]:
                        continue
                    # If condition has unresolved runtime parameters, it cannot provide unconditional Allow or unconditional Deny
                    if c_eval["conditions_unresolved"]:
                        continue

                if effect == "Deny":
                    is_denied = True
                    break  # Explicit Deny wins immediately
                elif effect == "Allow":
                    is_allowed = True

        if is_allowed and not is_denied:
            matched_resources.append(res)

    return matched_resources


def evaluate_policy_allows_resources_with_provenance(
    policy_name: str = "",
    policy_arn: str = "",
    document: Any = None,
    resources: Any = None,
    principal: Optional[Dict[str, Any]] = None,
    account_id: str = "",
    **kwargs
) -> Tuple[Any, Any, Any]:
    """Evaluate which resources this policy allows, capturing rich provenance metadata and explicit deny records.

    Returns:
        (matched_resources, provenance_map, deny_map)
        where provenance_map maps resource canonical key -> provenance dict
        and deny_map maps resource canonical key -> explicit deny evidence dict
    """
    if "policy_doc" in kwargs:
        document = kwargs["policy_doc"]
    is_dict_call = False
    if "known_resources" in kwargs:
        kr = kwargs["known_resources"]
        if isinstance(kr, dict):
            res_list = []
            for r_arn, r_info in kr.items():
                r_type = r_info.get("type", "Resource")
                r_name = r_arn.split(":")[-1]
                res_list.append({
                    "id": r_arn,
                    "name": r_name,
                    "arn": r_arn,
                    "type": r_type,
                    "region": r_info.get("region", kwargs.get("default_region", "us-east-1"))
                })
            resources = res_list
            is_dict_call = True
        else:
            resources = kr

    statements = parse_policy_document(document)
    matched_resources: List[Dict[str, Any]] = []
    provenance_map: Dict[str, Dict[str, Any]] = {}
    deny_map: Dict[str, Dict[str, Any]] = {}

    service_prefix_map = {
        "S3": "s3",
        "Secrets": "secretsmanager",
        "Secret": "secretsmanager",
        "RDS": "rds",
        "DynamoDB": "dynamodb",
        "EC2": "ec2",
        "Lambda": "lambda",
    }

    for res in resources:
        res_type = res.get("type")
        if not res_type:
            continue

        service_prefix = service_prefix_map.get(res_type)
        if not service_prefix:
            continue

        res_ident = res.get("id") if res_type == "EC2" else (res.get("name") or res.get("id") or "")
        res_arn = res.get("arn") or f"arn:aws:{service_prefix}:::{res_ident}"
        res_key = str(res_ident)

        is_allowed = False
        is_denied = False
        allow_stmt_evidence: Optional[Dict[str, Any]] = None
        deny_stmt_evidence: Optional[Dict[str, Any]] = None

        for stmt in statements:
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            not_actions = stmt.get("NotAction", [])
            resources_pat = stmt.get("Resource", [])
            not_resources = stmt.get("NotResource", [])
            sid = stmt.get("Sid") or "Statement"

            # Check if this statement applies to this resource's service & resource-specific actions
            matched_act = find_statement_matched_action(actions, not_actions, res_type, service_prefix)
            if not matched_act:
                continue

            # Check if this statement applies to this resource's ARN
            resource_matches = False
            matched_pat = ""
            for res_pattern in (resources_pat or ["*"]):
                if match_resource_arn(res_pattern, not_resources, res):
                    resource_matches = True
                    matched_pat = res_pattern
                    break

            if resource_matches:
                # Use the exact matched action for this resource
                matched_action = matched_act

                # Evaluate Condition block
                condition_status = "NONE"
                cond = stmt.get("Condition")
                if cond:
                    c_eval = evaluate_condition_block(cond, principal or {}, account_id)
                    if c_eval["is_violated"]:
                        continue
                    if c_eval["conditions_unresolved"]:
                        # Cannot provide unconditional Allow or unconditional Deny
                        continue
                    condition_status = "SATISFIED"

                if effect == "Deny":
                    is_denied = True
                    deny_stmt_evidence = {
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "statement_sid": sid,
                        "effect": "Deny",
                        "action": matched_action,
                        "resource": res_ident,
                        "resource_arn": res_arn,
                        "decision": "DENIED",
                        "why": f"Explicit Deny in statement '{sid}' on action '{matched_action}' overrides access",
                    }
                    break  # Explicit Deny wins immediately
                elif effect == "Allow":
                    is_allowed = True
                    allow_stmt_evidence = {
                        "edge_type": "ALLOWS",
                        "source": "IAM",
                        "principal": principal.get("arn") or principal.get("name") if principal else policy_arn,
                        "principal_type": principal.get("type", "Policy") if principal else "Policy",
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "statement_sid": sid,
                        "effect": "Allow",
                        "action": matched_action,
                        "resource": res_ident,
                        "resource_arn": res_arn,
                        "condition_status": condition_status,
                        "decision": "ALLOWED",
                        "region": res.get("region", "global"),
                        "why": f"Matched IAM policy statement '{sid}' allowing '{matched_action}' on resource '{res_arn}'",
                        "evidence": {
                            "statement_sid": sid,
                            "effect": "Allow",
                            "action": matched_action,
                            "resource_pattern": matched_pat,
                            "condition_status": condition_status,
                        }
                    }

        if is_denied and deny_stmt_evidence:
            deny_map[res_key] = deny_stmt_evidence

        if is_allowed and not is_denied and allow_stmt_evidence:
            matched_resources.append(res)
            allow_stmt_evidence["decision"] = "ALLOWED"
            act_val = allow_stmt_evidence.get("action", "*")
            allow_stmt_evidence["action"] = act_val
            allow_stmt_evidence["relationship_type"] = classify_resource_relationship(res_type, act_val)
            sid_val = allow_stmt_evidence.get("statement_sid", "Statement")
            allow_stmt_evidence["why"] = f"Statement '{sid_val}' in policy '{policy_name}' allows '{act_val}' on {res_type} '{res_ident}'"
            provenance_map[res_key] = allow_stmt_evidence

    if is_dict_call:
        allowed_arns = [r["arn"] for r in matched_resources]
        return allowed_arns, list(provenance_map.values()), list(deny_map.values())

    return matched_resources, provenance_map, deny_map


def check_resource_explicitly_denied(
    applicable_docs: List[Any],
    resource: Dict[str, Any],
    principal: Optional[Dict[str, Any]] = None,
    account_id: str = "",
) -> bool:
    """Check if ANY statement across all applicable policy documents has an explicit Deny for resource.

    Evaluates Action, NotAction, Resource, NotResource, and Condition blocks.
    Deterministic conditions that are violated do not apply.
    Conditions with unresolved runtime parameters do not unconditionally deny.
    """
    res_type = resource.get("type")
    if not res_type:
        return False

    service_prefix_map = {
        "S3": "s3",
        "Secrets": "secretsmanager",
        "Secret": "secretsmanager",
        "RDS": "rds",
        "DynamoDB": "dynamodb",
        "EC2": "ec2",
        "Lambda": "lambda",
    }
    service_prefix = service_prefix_map.get(res_type)
    if not service_prefix:
        return False

    for doc in applicable_docs:
        statements = parse_policy_document(doc)
        for stmt in statements:
            if stmt.get("Effect") != "Deny":
                continue

            actions = stmt.get("Action", [])
            not_actions = stmt.get("NotAction", [])
            if not has_service_action(actions, not_actions, service_prefix):
                continue

            resources = stmt.get("Resource", [])
            not_resources = stmt.get("NotResource", [])
            res_matches = False
            for res_pattern in (resources or ["*"]):
                if match_resource_arn(res_pattern, not_resources, resource):
                    res_matches = True
                    break
            if not res_matches:
                continue

            cond = stmt.get("Condition")
            if cond:
                c_eval = evaluate_condition_block(cond, principal or {}, account_id)
                # If condition deterministically violated, Deny statement does not apply
                if c_eval["is_violated"]:
                    continue
                # If condition has unresolved runtime parameters, it cannot unconditionally deny
                if c_eval["conditions_unresolved"]:
                    continue

            return True

    return False



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
            not_actions = stmt.get("NotAction", [])
            resources = stmt.get("Resource", [])
            not_resources = stmt.get("NotResource", [])

            action_matches = False
            if actions:
                action_matches = any(match_action(a, "sts:assumerole") for a in actions)
            elif not_actions:
                action_matches = not any(match_action(na, "sts:assumerole") for na in not_actions)

            if not action_matches:
                continue

            # Check if this statement applies to role_arn
            if not_resources:
                if any(nr == "*" or (role_arn and fnmatchcase(role_arn.lower(), nr.lower())) for nr in not_resources):
                    continue

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
                b_not_actions = b_s.get("NotAction", [])
                b_resources = b_s.get("Resource", [])
                b_not_resources = b_s.get("NotResource", [])

                b_act_match = False
                if b_actions:
                    b_act_match = any(match_action(a, "sts:assumerole") for a in b_actions)
                elif b_not_actions:
                    b_act_match = not any(match_action(na, "sts:assumerole") for na in b_not_actions)

                if not b_act_match:
                    continue

                if b_not_resources:
                    if any(bnr == "*" or (role_arn and fnmatchcase(role_arn.lower(), bnr.lower())) for bnr in b_not_resources):
                        continue

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
                "authorization_scope": "identity_and_resource_policy_only",
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
                "authorization_scope": "identity_and_resource_policy_only",
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
                "authorization_scope": "identity_and_resource_policy_only",
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
                "authorization_scope": "identity_and_resource_policy_only",
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
            "authorization_scope": "identity_and_resource_policy_only",
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

    def _process_user(u_obj: Dict[str, Any], trust_type: str, cond_eval: Dict[str, Any], requires_call_perm_check: bool, stmt_sid: str = ""):
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
                "authorization_scope": "identity_and_resource_policy_only",
                "conditions_status": "conditional" if (all_unresolved or boundary_unresolved) else ("satisfied" if all_satisfied else "none"),
                "conditions_evaluated": all_evaluated,
                "conditions_satisfied": all_satisfied,
                "conditions_unresolved": all_unresolved,
                "call_permission_verified": call_verified,
                "statement_sid": stmt_sid or "TrustStatement",
                "action": "sts:AssumeRole",
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

    def _process_role(r_obj: Dict[str, Any], trust_type: str, cond_eval: Dict[str, Any], requires_call_perm_check: bool, stmt_sid: str = ""):
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
                "authorization_scope": "identity_and_resource_policy_only",
                "conditions_status": "conditional" if (all_unresolved or boundary_unresolved) else ("satisfied" if all_satisfied else "none"),
                "conditions_evaluated": all_evaluated,
                "conditions_satisfied": all_satisfied,
                "conditions_unresolved": all_unresolved,
                "call_permission_verified": call_verified,
                "statement_sid": stmt_sid or "TrustStatement",
                "action": "sts:AssumeRole",
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
        current_sid = stmt.get("Sid") or "TrustStatement"

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
                    _process_user(u, "wildcard", c_eval, requires_call_perm_check=True, stmt_sid=current_sid)
            for r in all_roles:
                if r["name"] == role_name:
                    continue
                c_eval = evaluate_trust_statement_condition(stmt_condition, r, account_id)
                if not c_eval["is_violated"]:
                    _process_role(r, "wildcard", c_eval, requires_call_perm_check=True, stmt_sid=current_sid)
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
                        _process_user(u, "wildcard", c_eval, requires_call_perm_check=True, stmt_sid=current_sid)
                for r in all_roles:
                    if r["name"] == role_name:
                        continue
                    c_eval = evaluate_trust_statement_condition(stmt_condition, r, account_id)
                    if not c_eval["is_violated"]:
                        _process_role(r, "wildcard", c_eval, requires_call_perm_check=True, stmt_sid=current_sid)
                continue

            # ── Account root ARN or bare account ID ──────────────────────────
            if p.endswith(":root") or (account_id and p == account_id):
                result["trust_is_broad"] = True
                result["trust_principal_types"].add("account_root")
                for u in all_users:
                    c_eval = evaluate_trust_statement_condition(stmt_condition, u, account_id)
                    if not c_eval["is_violated"]:
                        _process_user(u, "account_root", c_eval, requires_call_perm_check=True, stmt_sid=current_sid)
                for r in all_roles:
                    if r["name"] == role_name:
                        continue
                    c_eval = evaluate_trust_statement_condition(stmt_condition, r, account_id)
                    if not c_eval["is_violated"]:
                        _process_role(r, "account_root", c_eval, requires_call_perm_check=True, stmt_sid=current_sid)
                continue

            # ── Specific Role ARN ─────────────────────────────────────────────
            if ":role/" in p:
                r_name = p.split("/")[-1]
                r_obj = role_name_map.get(r_name) or role_arn_map.get(p)
                if r_obj:
                    c_eval = evaluate_trust_statement_condition(stmt_condition, r_obj, account_id)
                    if not c_eval["is_violated"]:
                        result["trust_principal_types"].add("exact_arn")
                        _process_role(r_obj, "exact_arn", c_eval, requires_call_perm_check=False, stmt_sid=current_sid)
                continue

            # ── Specific User ARN ─────────────────────────────────────────────
            if ":user/" in p:
                u_name = p.split("/")[-1]
                u_obj = user_name_map.get(u_name) or user_arn_map.get(p)
                if u_obj:
                    c_eval = evaluate_trust_statement_condition(stmt_condition, u_obj, account_id)
                    if not c_eval["is_violated"]:
                        result["trust_principal_types"].add("exact_arn")
                        _process_user(u_obj, "exact_arn", c_eval, requires_call_perm_check=False, stmt_sid=current_sid)
                continue

    return result


def classify_action_category(action: str) -> str:
    """Canonical classification of an IAM action into standard privilege tier.

    Used for visualization aggregation and access level categorization.
    Adheres to standard AWS IAM access level taxonomy (Admin, Write, Read, Execute, Delete, Assume, DB Connect).
    """
    act = (action or "").strip()
    if not act:
        return "ACCESS"
    if act in ("*", "*:*") or "administratoraccess" in act.lower():
        return "FULL ADMIN"
    act_lower = act.lower()
    if act_lower.startswith("sts:assumerole") or ":assumerole" in act_lower:
        return "ASSUME_ROLE"
    if act_lower.startswith("rds-db:connect"):
        return "DB_CONNECT"
    if act_lower.startswith("iam:") or "*admin*" in act_lower:
        return "ADMIN"

    verb = act_lower.split(":")[-1] if ":" in act_lower else act_lower
    if any(verb.startswith(p) for p in ("delete", "remove", "drop", "purge", "terminate", "detach")):
        return "DELETE"
    if any(verb.startswith(p) for p in ("invoke", "run", "start", "execute", "trigger")):
        return "EXECUTE"
    if any(verb.startswith(p) for p in ("put", "create", "update", "modify", "post", "batchwrite", "attach", "set", "write")):
        return "WRITE"
    if any(verb.startswith(p) for p in ("get", "list", "describe", "view", "batchget", "read", "lookup", "head", "download")):
        return "READ"
    return "ACCESS"

