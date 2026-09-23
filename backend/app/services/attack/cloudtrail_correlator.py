"""
CloudScope CloudTrail Security Activity Correlator.

Normalizes CloudTrail events, maps exact runtime activity types (ASSUMED_ROLE,
MODIFIED_POLICY, CREATED_ACCESS_KEY, ACCESSED_RESOURCE, SECURITY_EVENT),
synchronizes activity idempotently into Neo4j using eventId, connects ActivityEvent
nodes into the security graph, and correlates observed runtime events with static
graph capabilities and attack paths.

Enforces clear 4-state semantic distinction:
- POSSIBLE_CAPABILITY (Static analysis: what an identity can potentially do)
- OBSERVED_ACTIVITY (CloudTrail: what activity actually occurred)
- CORRELATED_ACTIVITY (Verified static capability + matching CloudTrail event)
- OBSERVED_ATTACK_ACTIVITY (CloudTrail event matching exact transition of an identified attack path)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from app.database import execute_write
from app.services.scanner.inventory import AWSInventory
from app.services.graph.graph_loader import get_node_id

logger = logging.getLogger("scanner")

# Supported security-relevant event types
SECURITY_EVENT_TYPES = {
    "AssumeRole": "ASSUMED_ROLE",
    "PutRolePolicy": "MODIFIED_POLICY",
    "AttachRolePolicy": "MODIFIED_POLICY",
    "DetachRolePolicy": "MODIFIED_POLICY",
    "DeleteRolePolicy": "MODIFIED_POLICY",
    "PutUserPolicy": "MODIFIED_POLICY",
    "AttachUserPolicy": "MODIFIED_POLICY",
    "DetachUserPolicy": "MODIFIED_POLICY",
    "DeleteUserPolicy": "MODIFIED_POLICY",
    "PutGroupPolicy": "MODIFIED_POLICY",
    "AttachGroupPolicy": "MODIFIED_POLICY",
    "DetachGroupPolicy": "MODIFIED_POLICY",
    "CreatePolicyVersion": "MODIFIED_POLICY",
    "SetDefaultPolicyVersion": "MODIFIED_POLICY",
    "PutBucketPolicy": "MODIFIED_POLICY",
    "DeleteBucketPolicy": "MODIFIED_POLICY",
    "UpdateAssumeRolePolicy": "MODIFIED_POLICY",
    "CreateAccessKey": "CREATED_ACCESS_KEY",
    "CreateLoginProfile": "CREATED_ACCESS_KEY",
    "GetObject": "ACCESSED_RESOURCE",
    "PutObject": "ACCESSED_RESOURCE",
    "DeleteObject": "ACCESSED_RESOURCE",
    "GetSecretValue": "ACCESSED_RESOURCE",
    "DescribeDBInstances": "ACCESSED_RESOURCE",
    "RunInstances": "ACCESSED_RESOURCE",
    "StartInstances": "ACCESSED_RESOURCE",
    "StopInstances": "ACCESSED_RESOURCE",
    "TerminateInstances": "ACCESSED_RESOURCE",
    "RebootInstances": "ACCESSED_RESOURCE",
    "Invoke": "ACCESSED_RESOURCE",
}


def get_activity_type(event_name: str) -> str:
    """Classify the exact security activity relationship type from AWS event name."""
    return SECURITY_EVENT_TYPES.get(event_name, "SECURITY_EVENT")


def parse_timezone_aware_timestamp(event_time_raw: Any) -> Optional[datetime]:
    """Parse raw timestamp into a standardized timezone-aware datetime object.
    
    Returns None if missing, empty, or malformed.
    Never invents current time or falls back to datetime.now().
    Valid timestamps are guaranteed timezone-aware.
    """
    if isinstance(event_time_raw, datetime):
        if event_time_raw.tzinfo is None:
            return event_time_raw.replace(tzinfo=timezone.utc)
        return event_time_raw
    elif isinstance(event_time_raw, str) and event_time_raw.strip():
        raw_str = event_time_raw.strip()
        try:
            iso_str = raw_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
    return None


def normalize_principal(identity_input: Any) -> Tuple[str, str, str]:
    """Normalize principal identity to (principal_id, principal_type, principal_arn).
    
    Correctly distinguishes IAMUser, AssumedRole, Root, FederatedUser, and AWSService.
    Never invents fake account IDs (e.g. 123456789012) when account ID is missing.
    """
    if isinstance(identity_input, str):
        arn = identity_input
        if ":user/" in arn:
            return arn, "User", arn
        elif ":role/" in arn:
            return arn, "Role", arn
        elif ":assumed-role/" in arn:
            parts = arn.split(":assumed-role/")[1].split("/")
            role_name = parts[0]
            acc = arn.split(":")[4] if len(arn.split(":")) > 4 else "unknown"
            base_arn = f"arn:aws:iam::{acc}:role/{role_name}"
            return base_arn, "Role", base_arn
        elif ":root" in arn:
            return arn, "Root", arn
        elif arn.endswith(".amazonaws.com") or ":service/" in arn:
            return arn, "AWSService", arn
        return arn, "Principal", arn
    elif isinstance(identity_input, dict):
        p_type = identity_input.get("type", "IAMUser")
        arn = identity_input.get("arn", "")
        p_id = identity_input.get("principalId", "")
        user_name = identity_input.get("userName", "")
        account_id = identity_input.get("accountId") or ""

        if p_type == "IAMUser":
            if arn:
                norm_arn = arn
            elif account_id and user_name:
                norm_arn = f"arn:aws:iam::{account_id}:user/{user_name}"
            elif user_name:
                norm_arn = f"arn:aws:iam::unknown:user/{user_name}"
            else:
                norm_arn = p_id or "unknown"
            return norm_arn, "User", norm_arn
        elif p_type == "AssumedRole":
            if ":assumed-role/" in arn:
                parts = arn.split(":assumed-role/")[1].split("/")
                role_name = parts[0]
                acc = arn.split(":")[4] if len(arn.split(":")) > 4 else (account_id or "unknown")
                base_arn = f"arn:aws:iam::{acc}:role/{role_name}"
                return base_arn, "Role", base_arn
            elif ":role/" in arn:
                return arn, "Role", arn
            return arn or p_id or "unknown", "Role", arn or p_id or "unknown"
        elif p_type == "Root":
            if arn:
                norm_arn = arn
            elif account_id:
                norm_arn = f"arn:aws:iam::{account_id}:root"
            else:
                norm_arn = "arn:aws:iam::unknown:root"
            return norm_arn, "Root", norm_arn
        elif p_type == "FederatedUser":
            return arn or p_id or "unknown", "FederatedUser", arn or p_id or "unknown"
        elif p_type in ["AWSService", "Service"] or "invokedBy" in identity_input:
            svc_name = identity_input.get("invokedBy") or identity_input.get("service") or arn or p_id or "AWSService"
            return svc_name, "AWSService", svc_name
        return arn or p_id or "unknown", p_type, arn or p_id or "unknown"
    return str(identity_input), "Unknown", str(identity_input)


def normalize_cloudtrail_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw boto3 or dictionary CloudTrail event into a structured security event object."""
    event_id = raw_event.get('EventId', '') or raw_event.get('event_id', '') or ''
    event_name = raw_event.get('EventName', 'Unknown') or raw_event.get('event_name', 'Unknown')
    event_time_raw = raw_event.get('EventTime') or raw_event.get('event_time')
    dt = parse_timezone_aware_timestamp(event_time_raw)
    event_time = dt.isoformat() if dt is not None else None
    timestamp_valid = dt is not None

    username = raw_event.get('Username') or raw_event.get('username') or raw_event.get('actor') or 'Unknown'

    # Parse nested CloudTrailEvent JSON string if present
    ct_json_str = raw_event.get('CloudTrailEvent', '{}')
    ct_detail: Dict[str, Any] = {}
    if isinstance(ct_json_str, str):
        try:
            ct_detail = json.loads(ct_json_str)
        except Exception:
            ct_detail = {}
    elif isinstance(ct_json_str, dict):
        ct_detail = ct_json_str

    user_identity = ct_detail.get('userIdentity') or raw_event.get('userIdentity', {})
    actor_arn = user_identity.get('arn', '') or raw_event.get('actor_arn', '') or ''
    actor_type = user_identity.get('type', 'IAMUser')
    actor_name = user_identity.get('userName') or username or 'Unknown'

    # If principal is an AssumedRole, extract base role name
    if actor_type == 'AssumedRole' or ':assumed-role/' in actor_arn:
        if ':assumed-role/' in actor_arn:
            parts = actor_arn.split(':assumed-role/')[1].split('/')
            actor_name = parts[0]
            actor_type = 'AssumedRole'
    elif ':user/' in actor_arn:
        actor_name = actor_arn.split('/')[-1]
        actor_type = 'IAMUser'
    elif ':root' in actor_arn or actor_type == 'Root':
        actor_name = 'root'
        actor_type = 'Root'
    elif actor_type in ['AWSService', 'Service'] or user_identity.get('invokedBy'):
        actor_name = user_identity.get('invokedBy') or actor_name
        actor_type = 'AWSService'

    event_source = ct_detail.get('eventSource', raw_event.get('event_source', raw_event.get('EventSource', '')))
    account_id = user_identity.get('accountId') or ct_detail.get('recipientAccountId', raw_event.get('account_id', ''))
    source_ip = raw_event.get('SourceIPAddress') or ct_detail.get('sourceIPAddress', raw_event.get('source_ip', 'Unknown'))
    user_agent = raw_event.get('UserAgent') or ct_detail.get('userAgent', raw_event.get('user_agent', ''))
    region = ct_detail.get('awsRegion', raw_event.get('region', raw_event.get('aws_region', 'global')))

    raw_req_params = raw_event.get('RequestParameters') or ct_detail.get('requestParameters') or raw_event.get('request_parameters') or {}
    if isinstance(raw_req_params, str):
        try:
            req_params = json.loads(raw_req_params)
        except Exception:
            req_params = {}
    else:
        req_params = raw_req_params

    read_only_val = raw_event.get('ReadOnly', raw_event.get('read_only', ct_detail.get('readOnly', False)))
    read_only = str(read_only_val).lower() == 'true' if isinstance(read_only_val, (str, bool)) else bool(read_only_val)

    error_code = raw_event.get('ErrorCode') or ct_detail.get('errorCode')
    error_message = raw_event.get('ErrorMessage') or ct_detail.get('errorMessage')

    target_arn = ""
    target_name = ""
    target_type = "Resource"

    # Extract event-specific target information
    if event_name == 'AssumeRole':
        target_arn = req_params.get('roleArn', '') or raw_event.get('target_arn', '')
        if target_arn:
            target_name = target_arn.split('/')[-1]
        elif 'roleName' in req_params:
            target_name = req_params['roleName']
        elif raw_event.get('target') or raw_event.get('target_name'):
            target_name = raw_event.get('target') or raw_event.get('target_name')
        target_type = "Role"
    elif event_name in ['PutRolePolicy', 'AttachRolePolicy', 'DetachRolePolicy', 'DeleteRolePolicy', 'UpdateAssumeRolePolicy']:
        target_name = req_params.get('roleName', '')
        target_type = "Role"
        target_arn = req_params.get('policyArn', '')
    elif event_name in ['PutUserPolicy', 'AttachUserPolicy', 'DetachUserPolicy', 'DeleteUserPolicy']:
        target_name = req_params.get('userName', '')
        target_type = "User"
        target_arn = req_params.get('policyArn', '')
    elif event_name in ['PutGroupPolicy', 'AttachGroupPolicy', 'DetachGroupPolicy']:
        target_name = req_params.get('groupName', '')
        target_type = "Group"
        target_arn = req_params.get('policyArn', '')
    elif event_name in ['CreatePolicyVersion', 'SetDefaultPolicyVersion']:
        target_arn = req_params.get('policyArn', '')
        target_name = target_arn.split('/')[-1] if target_arn else 'Policy'
        target_type = "Policy"
    elif event_name in ['PutBucketPolicy', 'DeleteBucketPolicy']:
        target_name = req_params.get('bucketName', '')
        target_type = "S3"
    elif event_name in ['CreateAccessKey', 'CreateLoginProfile']:
        target_name = req_params.get('userName') or actor_name
        target_type = "User"
    elif event_name in ['RunInstances', 'StartInstances', 'StopInstances', 'TerminateInstances']:
        target_type = "EC2"
        inst_set = req_params.get('instanceSet') or req_params.get('instancesSet') or {}
        items = inst_set.get('items', []) if isinstance(inst_set, dict) else []
        if items and isinstance(items[0], dict) and 'instanceId' in items[0]:
            target_name = items[0]['instanceId']
        else:
            res_list = raw_event.get('Resources', [])
            if res_list:
                target_name = res_list[0].get('ResourceName', 'EC2')

    # Fallback to resources list in raw event
    if not target_name:
        res_list = raw_event.get('Resources', [])
        if res_list:
            res_item = res_list[0]
            raw_target = res_item.get('ARN') or res_item.get('arn') or res_item.get('ResourceName') or ''
            if raw_target:
                target_arn = raw_target
                target_name = raw_target
                if ':role/' in raw_target:
                    target_type = "Role"
                    target_name = raw_target.split('/')[-1]
                elif ':user/' in raw_target:
                    target_type = "User"
                    target_name = raw_target.split('/')[-1]
                elif 's3:::' in raw_target:
                    target_type = "S3"
                    target_name = raw_target.replace('arn:aws:s3:::', '').split('/')[0]
                elif 'secretsmanager:' in raw_target:
                    target_type = "Secret"
                    target_name = raw_target.split(':secret:')[-1]

    if not target_name and (raw_event.get('target') or raw_event.get('target_name')):
        target_name = raw_event.get('target') or raw_event.get('target_name')

    activity_type = get_activity_type(event_name)
    is_high_risk = activity_type in ["ASSUMED_ROLE", "MODIFIED_POLICY", "CREATED_ACCESS_KEY"]

    sec_mod_events = [
        "PutRolePolicy", "AttachRolePolicy", "DetachRolePolicy", "DeleteRolePolicy",
        "PutUserPolicy", "AttachUserPolicy", "DetachUserPolicy", "DeleteUserPolicy",
        "PutGroupPolicy", "AttachGroupPolicy", "DetachGroupPolicy", "DeleteGroupPolicy",
        "CreatePolicyVersion", "SetDefaultPolicyVersion", "PutBucketPolicy", "DeleteBucketPolicy",
        "UpdateAssumeRolePolicy", "CreateAccessKey", "CreateLoginProfile"
    ]
    is_sec_mod = event_name in sec_mod_events

    return {
        "event_id": event_id,
        "event_name": event_name,
        "event_source": event_source,
        "activity_type": activity_type,
        "event_time": event_time,
        "timestamp": event_time,
        "timestamp_valid": timestamp_valid,
        "aws_region": region,
        "region": region,
        "account_id": account_id,
        "principal": actor_arn or actor_name,
        "actor_name": actor_name,
        "actor_arn": actor_arn,
        "actor_type": actor_type,
        "principal_type": actor_type,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "target_name": target_name,
        "target_type": target_type,
        "target_arn": target_arn,
        "request_parameters": req_params,
        "resources": raw_event.get('Resources', []),
        "is_high_risk": is_high_risk,
        "is_security_modification": is_sec_mod,
        "read_only": read_only,
        "error_code": error_code,
        "error_message": error_message,
        "raw_details": ct_detail
    }


def map_principal_to_node_id(actor_name: str, actor_arn: str, actor_type: str) -> str:
    """Map normalized principal information to a stable graph node ID."""
    if actor_type == 'Role' or actor_type == 'AssumedRole' or ':role/' in actor_arn or ':assumed-role/' in actor_arn:
        return get_node_id("Role", actor_name)
    return get_node_id("User", actor_name)


def sync_activity_into_neo4j(normalized_events: List[Dict[str, Any]]):
    """Write normalized CloudTrail events into Neo4j using idempotent MERGE on eventId.
    Connects ActivityEvent node:
    (Principal) -[:OBSERVED_ACTIVITY]-> (:ActivityEvent) -[:TARGETS]-> (Target)
    Also preserves dynamic activity edges for graph visualization.
    """
    for ev in normalized_events:
        event_id = ev.get("event_id")
        if not event_id:
            continue

        actor_name = ev["actor_name"]
        target_name = ev["target_name"]
        activity_type = ev["activity_type"]

        actor_node_id = map_principal_to_node_id(actor_name, ev.get("actor_arn", ""), ev.get("actor_type", "IAMUser"))
        target_node_id = get_node_id(ev["target_type"], target_name) if target_name else None

        try:
            # 1. Idempotent MERGE of ActivityEvent node
            execute_write(
                """
                MERGE (a:ActivityEvent {eventId: $eventId})
                SET a.eventName = $eventName,
                    a.activityType = $activityType,
                    a.timestamp = $timestamp,
                    a.sourceIp = $sourceIp,
                    a.region = $region,
                    a.actor = $actor,
                    a.target = $target,
                    a.userAgent = $userAgent,
                    a.accountId = $accountId
                """,
                {
                    "eventId": event_id,
                    "eventName": ev["event_name"],
                    "activityType": activity_type,
                    "timestamp": ev.get("event_time") or "",
                    "sourceIp": ev.get("source_ip", ""),
                    "region": ev.get("region", ""),
                    "actor": actor_name,
                    "target": target_name or "N/A",
                    "userAgent": ev.get("user_agent", ""),
                    "accountId": ev.get("account_id", "")
                }
            )

            # 2. Connect actor to ActivityEvent: (u)-[:OBSERVED_ACTIVITY {eventId}]->(a)
            execute_write(
                """
                MATCH (u {id: $actor_id}), (a:ActivityEvent {eventId: $eventId})
                MERGE (u)-[r:OBSERVED_ACTIVITY {eventId: $eventId}]->(a)
                SET r.timestamp = $timestamp,
                    r.eventName = $eventName,
                    r.is_activity = true
                """,
                {
                    "actor_id": actor_node_id,
                    "eventId": event_id,
                    "timestamp": ev.get("event_time") or "",
                    "eventName": ev["event_name"]
                }
            )

            # 3. Connect ActivityEvent to target: (a)-[:TARGETS {eventId}]->(tgt)
            if target_node_id and target_name:
                execute_write(
                    """
                    MATCH (a:ActivityEvent {eventId: $eventId}), (tgt {id: $target_id})
                    MERGE (a)-[r:TARGETS {eventId: $eventId}]->(tgt)
                    SET r.timestamp = $timestamp,
                        r.eventName = $eventName,
                        r.is_activity = true
                    """,
                    {
                        "eventId": event_id,
                        "target_id": target_node_id,
                        "timestamp": ev.get("event_time") or "",
                        "eventName": ev["event_name"]
                    }
                )

                # 4. Preserve dynamic activity edge for attack-path visualization
                if not ev.get("error_code"):
                    execute_write(
                        f"""
                        MATCH (u {{id: $actor_id}}), (tgt {{id: $target_id}})
                        MERGE (u)-[r:{activity_type} {{eventId: $eventId}}]->(tgt)
                        SET r.timestamp = $timestamp,
                            r.sourceIp = $sourceIp,
                            r.eventName = $eventName,
                            r.is_activity = true
                        """,
                        {
                            "actor_id": actor_node_id,
                            "target_id": target_node_id,
                            "eventId": event_id,
                            "timestamp": ev.get("event_time") or "",
                            "sourceIp": ev.get("source_ip", ""),
                            "eventName": ev["event_name"]
                        }
                    )
        except Exception as e:
            logger.debug(f"Could not record activity in Neo4j for event {event_id}: {e}")


def check_verified_static_capability(
    G: nx.DiGraph,
    sources: List[str],
    targets: List[str],
    activity_type: str,
    event_name: str
) -> Tuple[bool, Optional[str], Optional[str], str]:
    """Verify if a static authorization edge or canonical authorization path exists in G.
    Returns (has_capability, matched_src, matched_tgt, matched_rel).
    
    Strict rules:
    - Never infer capability merely because target exists in inventory or is a known role.
    - AssumeRole requires verified static CAN_ASSUME edge.
    - Resource access requires verified static ALLOWS or DB_CONNECT edge (direct or via attached Policy).
    """
    if not G:
        return False, None, None, "NONE"

    for s in sources:
        if not G.has_node(s):
            continue
        for t in targets:
            if not G.has_node(t):
                continue

            # 1. Direct static authorization edge
            if G.has_edge(s, t):
                edge_data = G.get_edge_data(s, t)
                rel = edge_data.get("relationship") or edge_data.get("label") or edge_data.get("type") or ""
                # Static authorization edges
                if activity_type == "ASSUMED_ROLE" and rel == "CAN_ASSUME":
                    return True, s, t, "CAN_ASSUME"
                elif activity_type in ["ACCESSED_RESOURCE", "SECURITY_EVENT"]:
                    if rel in ["ALLOWS", "DB_CONNECT"]:
                        return True, s, t, rel
                elif activity_type == "MODIFIED_POLICY" and rel in ["HAS_POLICY", "ALLOWS"]:
                    return True, s, t, rel

            # 2. Canonical Policy path for resource access:
            # (Identity) -[HAS_POLICY]-> (Policy) -[ALLOWS / DB_CONNECT]-> (Resource)
            if activity_type in ["ACCESSED_RESOURCE", "SECURITY_EVENT"]:
                for neighbor in G.successors(s):
                    n_data = G.nodes.get(neighbor, {})
                    n_type = n_data.get("type", "")
                    s_to_n = G.get_edge_data(s, neighbor, default={})
                    s_rel = s_to_n.get("relationship") or s_to_n.get("type") or ""
                    
                    if n_type == "Policy" and s_rel == "HAS_POLICY":
                        if G.has_edge(neighbor, t):
                            pol_to_t = G.get_edge_data(neighbor, t, default={})
                            t_rel = pol_to_t.get("relationship") or pol_to_t.get("type") or ""
                            if t_rel in ["ALLOWS", "DB_CONNECT"]:
                                return True, s, t, t_rel
                    
                    # Or via group membership: (User) -[MEMBER_OF]-> (Group) -[HAS_POLICY]-> (Policy) -[ALLOWS]-> (Resource)
                    elif n_type == "Group" and s_rel == "MEMBER_OF":
                        for g_pol in G.successors(neighbor):
                            g_data = G.nodes.get(g_pol, {})
                            if g_data.get("type") == "Policy" and G.has_edge(g_pol, t):
                                g_edge = G.get_edge_data(g_pol, t, default={})
                                if g_edge.get("relationship") in ["ALLOWS", "DB_CONNECT"]:
                                    return True, s, t, g_edge.get("relationship")

    return False, None, None, "NONE"


def match_attack_path_transition(
    path: Dict[str, Any],
    sources: List[str],
    targets: List[str],
    activity_type: str,
    event_name: str
) -> Optional[Dict[str, Any]]:
    """Match a CloudTrail event against an exact transition step along the attack path.
    
    Must NOT match merely because actor and target appear somewhere in the path.
    Must match the exact logical transition:
    - AssumeRole: (u, "CAN_ASSUME", v) where u matches actor and v matches target role.
    - Resource access: (u, "ALLOWS", v) or (u, "DB_CONNECT", v) where u is actor (or actor's attached policy in path) and v is target.
    """
    nodes = path.get("nodes") or path.get("ordered_nodes") or []
    rels = path.get("ordered_relationships") or path.get("orderedRelationships") or []

    if not nodes or not rels or len(nodes) < 2:
        return None

    def node_matches(node_obj: Any, id_list: List[str]) -> bool:
        if isinstance(node_obj, str):
            n_ids = [node_obj, node_obj.split("/")[-1]]
        elif isinstance(node_obj, dict):
            n_id = node_obj.get("id", "")
            n_name = node_obj.get("name", "")
            n_arn = node_obj.get("arn", "")
            n_ids = [n_id, n_name, n_arn]
            if "/" in n_id:
                n_ids.append(n_id.split("/")[-1])
            if "/" in n_name:
                n_ids.append(n_name.split("/")[-1])
            if "/" in n_arn:
                n_ids.append(n_arn.split("/")[-1])
        else:
            n_ids = [str(node_obj)]

        return any(x and x in id_list for x in n_ids)

    num_steps = min(len(rels), len(nodes) - 1)
    for i in range(num_steps):
        u_node = nodes[i]
        v_node = nodes[i + 1]
        rel = rels[i]

        u_matches_actor = node_matches(u_node, sources)
        v_matches_target = node_matches(v_node, targets)

        # 1. Direct transition match:
        # e.g. Alice -> CAN_ASSUME -> AdminRole
        if activity_type == "ASSUMED_ROLE":
            if u_matches_actor and v_matches_target and rel in ["CAN_ASSUME", "ASSUMED_ROLE"]:
                return {
                    "step_index": i,
                    "from_node": u_node.get("name") if isinstance(u_node, dict) else str(u_node),
                    "to_node": v_node.get("name") if isinstance(v_node, dict) else str(v_node),
                    "relationship": rel,
                    "event_name": event_name,
                    "description": f"Step {i + 1}: {rel} from {u_node} to {v_node}"
                }

        # 2. Resource access match:
        elif activity_type == "ACCESSED_RESOURCE":
            # Direct: Identity -> ALLOWS -> Resource
            if u_matches_actor and v_matches_target and rel in ["ALLOWS", "DB_CONNECT"]:
                return {
                    "step_index": i,
                    "from_node": u_node.get("name") if isinstance(u_node, dict) else str(u_node),
                    "to_node": v_node.get("name") if isinstance(v_node, dict) else str(v_node),
                    "relationship": rel,
                    "event_name": event_name,
                    "description": f"Step {i + 1}: {rel} to {v_node}"
                }
            # Canonical: Identity -> HAS_POLICY -> Policy -> ALLOWS -> Resource
            if v_matches_target and rel in ["ALLOWS", "DB_CONNECT"]:
                if i > 0 and node_matches(nodes[i - 1], sources):
                    prev_rel = rels[i - 1]
                    if prev_rel in ["HAS_POLICY", "MEMBER_OF"]:
                        return {
                            "step_index": i,
                            "from_node": nodes[i - 1].get("name") if isinstance(nodes[i - 1], dict) else str(nodes[i - 1]),
                            "via_node": u_node.get("name") if isinstance(u_node, dict) else str(u_node),
                            "to_node": v_node.get("name") if isinstance(v_node, dict) else str(v_node),
                            "relationship": rel,
                            "event_name": event_name,
                            "description": f"Step {i + 1}: {rel} via policy to {v_node}"
                        }

    return None


def correlate_activity_with_graph(
    raw_events: Any,
    inventory: Any = None,
    G: Any = None,
    attack_paths: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Correlate normalized CloudTrail events with static graph topology and attack paths.
    
    Produces explicit correlation classifications:
    - POSSIBLE_CAPABILITY: static capability exists, no activity recorded
    - OBSERVED_ACTIVITY: event recorded, no matching static capability/path
    - CORRELATED_ACTIVITY: event matches static permission/capability
    - OBSERVED_ATTACK_ACTIVITY: event matches an exact attack path transition
    """
    if isinstance(raw_events, nx.DiGraph):
        real_G = raw_events
        real_events = inventory or []
        real_inventory = AWSInventory()
    elif isinstance(inventory, nx.DiGraph):
        real_G = inventory
        real_events = raw_events or []
        real_inventory = AWSInventory()
    else:
        real_G = G if G is not None else nx.DiGraph()
        real_events = raw_events or []
        real_inventory = inventory if inventory is not None else AWSInventory()

    active_attack_paths = attack_paths
    if active_attack_paths is None and real_G and real_G.number_of_nodes() > 0:
        try:
            from app.services.attack.path_engine import find_attack_paths
            active_attack_paths = find_attack_paths(real_G)
        except Exception:
            active_attack_paths = None

    # 1. Deduplicate incoming events by event_id for strict idempotency
    seen_ids: Set[str] = set()
    deduped_raw: List[Dict[str, Any]] = []
    for raw in real_events:
        eid = raw.get("EventId") or raw.get("event_id") or ""
        if eid:
            if eid in seen_ids:
                continue
            seen_ids.add(eid)
        deduped_raw.append(raw)

    normalized_events = [normalize_cloudtrail_event(e) for e in deduped_raw]

    # 2. Sync activity into Neo4j idempotently
    sync_activity_into_neo4j(normalized_events)

    activity_edges: List[Dict[str, Any]] = []
    correlated_findings: List[Dict[str, Any]] = []

    role_risk_map = {r.get('name', ''): r.get('riskScore', 0) for r in getattr(real_inventory, 'roles', [])}
    matched_path_ids: Set[str] = set()

    for ev in normalized_events:
        event_id = ev["event_id"]
        actor = ev["actor_name"]
        target = ev["target_name"]
        ev_name = ev["event_name"]
        act_type = ev["activity_type"]
        actor_type = ev["actor_type"]
        actor_arn = ev.get("actor_arn", "")
        target_arn = ev.get("target_arn", "")
        is_error = bool(ev.get("error_code"))
        error_code = ev.get("error_code")

        if not actor or actor == "Unknown":
            continue

        actor_node_id = map_principal_to_node_id(actor, actor_arn, actor_type)
        target_node_id = get_node_id(ev["target_type"], target) if target else None

        # Build candidate identifiers for actor and target
        possible_sources = [s for s in [actor_arn, actor_node_id, actor] if s]
        if ":assumed-role/" in actor_arn:
            try:
                acc = actor_arn.split(":")[4]
                base_role_arn = f"arn:aws:iam::{acc}:role/{actor}"
                possible_sources.append(base_role_arn)
            except Exception:
                pass

        possible_targets = [t for t in [target_arn, target_node_id, target] if t]
        for r_entry in ev.get("resources", []):
            r_arn = r_entry.get("ARN") or r_entry.get("ResourceName", "")
            if r_arn:
                possible_targets.append(r_arn)
                if "/" in r_arn and "arn:aws:s3:::" in r_arn:
                    possible_targets.append(r_arn.split("/")[0])

        # 3. Determine actor and target representations in real_G
        actor_in_g = None
        target_in_g = None
        if real_G:
            for s in possible_sources:
                if real_G.has_node(s):
                    actor_in_g = s
                    break
            for t in possible_targets:
                if real_G.has_node(t):
                    target_in_g = t
                    break

        # 4. ActivityEvent Node Model: User/Role ──OBSERVED_ACTIVITY──> ActivityEvent ──TARGETS──> Target
        evt_node_id = f"event:{event_id}" if event_id else f"event:{actor}_{ev_name}"
        if real_G is not None:
            if not real_G.has_node(evt_node_id):
                real_G.add_node(
                    evt_node_id,
                    type="ActivityEvent",
                    eventId=event_id,
                    eventName=ev_name,
                    activityType=act_type,
                    timestamp=ev.get("event_time"),
                    source_ip=ev.get("source_ip"),
                    region=ev.get("region"),
                    name=ev_name,
                    actor=actor,
                    target=target,
                    is_error=is_error,
                    error_code=error_code
                )

            # Connect actor to ActivityEvent
            src_node = actor_in_g or actor_arn or actor_node_id or actor
            if real_G.has_node(src_node):
                real_G.add_edge(
                    src_node,
                    evt_node_id,
                    relationship="OBSERVED_ACTIVITY",
                    type="OBSERVED_ACTIVITY",
                    label="OBSERVED_ACTIVITY",
                    eventId=event_id,
                    timestamp=ev.get("event_time"),
                    is_activity=True
                )

            # Connect ActivityEvent to Target
            tgt_node = target_in_g or target_arn or target_node_id or target
            if tgt_node and real_G.has_node(tgt_node):
                real_G.add_edge(
                    evt_node_id,
                    tgt_node,
                    relationship="TARGETS",
                    type="TARGETS",
                    label="TARGETS",
                    eventId=event_id,
                    timestamp=ev.get("event_time"),
                    is_activity=True
                )

        # 5. Check Verified Static Capability
        has_static_cap, matched_src, matched_tgt, matched_rel = check_verified_static_capability(
            real_G, possible_sources, possible_targets, act_type, ev_name
        )

        # 6. Check Exact Attack Path Transition Match
        matched_transition = None
        matching_path = None
        if active_attack_paths and not is_error:
            for ap in active_attack_paths:
                m = match_attack_path_transition(ap, possible_sources, possible_targets, act_type, ev_name)
                if m:
                    matched_transition = m
                    matching_path = ap
                    break

        target_risk = role_risk_map.get(target, 0)

        # 7. Classify Finding
        if is_error:
            # Denied events must NEVER be treated as successful transitions or correlated authorizations
            finding_type = "OBSERVED_ACTIVITY"
            matched_static_rel = "NONE"
            static_path_id = None
            reason = f"Observed CloudTrail denied/error event '{ev_name}' with error code '{error_code}' by '{actor}'."
        elif matching_path and matched_transition:
            finding_type = "OBSERVED_ATTACK_ACTIVITY"
            matched_static_rel = matched_transition.get("relationship", act_type)
            static_path_id = matching_path.get("id", "path-unknown")
            matched_path_ids.add(static_path_id)
            matching_path["correlation_status"] = "OBSERVED_ATTACK_ACTIVITY"
            matching_path.setdefault("observed_activity", []).append({
                **ev,
                "matched_transition": matched_transition
            })
            if act_type == "ASSUMED_ROLE":
                action_desc = f"principal '{actor}' actively assumed privileged role '{target}'"
            else:
                action_desc = f"principal '{actor}' executed '{ev_name}' against target '{target}'"
            reason = (
                f"Observed activity consistent with identified attack path '{static_path_id}' "
                f"(matched transition: {matched_transition.get('description')}): {action_desc}."
            )
            # Annotate static edge in real_G
            if has_static_cap and matched_src and matched_tgt and real_G.has_edge(matched_src, matched_tgt):
                real_G[matched_src][matched_tgt]["correlation_status"] = "CORRELATED_ACTIVITY"
                real_G[matched_src][matched_tgt]["last_observed_event_id"] = event_id
        elif has_static_cap:
            finding_type = "CORRELATED_ACTIVITY"
            matched_static_rel = matched_rel
            static_path_id = None
            if act_type == "ASSUMED_ROLE":
                action_desc = f"'{actor}' actively assumed privileged role '{target}'"
            else:
                action_desc = f"'{actor}' executed '{ev_name}' against '{target}'"
            reason = (
                f"Observed activity matches verified static IAM authorization in the security graph: "
                f"{action_desc} via '{matched_static_rel}'."
            )
            # Annotate static edge in real_G
            if matched_src and matched_tgt and real_G.has_edge(matched_src, matched_tgt):
                real_G[matched_src][matched_tgt]["correlation_status"] = "CORRELATED_ACTIVITY"
                real_G[matched_src][matched_tgt]["last_observed_event_id"] = event_id
        else:
            finding_type = "OBSERVED_ACTIVITY"
            matched_static_rel = "NONE"
            static_path_id = None
            reason = f"Observed CloudTrail management event '{ev_name}' executed by '{actor}' without verified static capability."

            # If AssumeRole was observed without static permission, create anomalous dynamic edge
            if act_type == "ASSUMED_ROLE" and real_G and actor_in_g and target_in_g and not is_error:
                real_G.add_edge(
                    actor_in_g,
                    target_in_g,
                    relationship="ASSUMED_ROLE",
                    correlation_status="OBSERVED_ACTIVITY",
                    is_anomalous=True,
                    eventId=event_id,
                    last_observed_event_id=event_id
                )

        # 8. Preserve dynamic relationship for graph visualization (when successful)
        if not is_error and actor_in_g and target_in_g and real_G is not None:
            # Preserve dynamic edge without overwriting static authorization edges
            if not real_G.has_edge(actor_in_g, target_in_g):
                real_G.add_edge(
                    actor_in_g,
                    target_in_g,
                    relationship=act_type,
                    label=act_type,
                    type=act_type,
                    eventId=event_id,
                    timestamp=ev.get("event_time"),
                    is_activity=True
                )
            activity_edges.append({
                "source": actor_in_g,
                "target": target_in_g,
                "label": act_type,
                "type": act_type,
                "event_id": event_id,
                "timestamp": ev.get("event_time"),
                "source_ip": ev.get("source_ip"),
                "sourceIp": ev.get("source_ip"),
                "is_active": True
            })

        severity = "critical" if (target_risk >= 80 or finding_type == "OBSERVED_ATTACK_ACTIVITY") else ("high" if target_risk >= 60 else "medium")

        finding = {
            "id": f"corr-{event_id}",
            "type": finding_type,
            "finding_type": finding_type,
            "title": f"Observed {ev_name} Activity by {actor}",
            "actor": actor,
            "principal": ev.get("principal", actor),
            "actor_node_id": actor_node_id,
            "target": target or "N/A",
            "target_node_id": target_node_id,
            "target_type": ev["target_type"],
            "event_id": event_id,
            "event_name": ev_name,
            "event_time": ev["event_time"],
            "timestamp": ev["event_time"],
            "timestamp_valid": ev.get("timestamp_valid", False),
            "activity_type": act_type,
            "source_ip": ev["source_ip"],
            "region": ev["region"],
            "aws_region": ev["aws_region"],
            "user_agent": ev["user_agent"],
            "severity": severity,
            "risk_score": max(target_risk, 30 if finding_type == "OBSERVED_ATTACK_ACTIVITY" else 15),
            "target_risk_score": target_risk,
            "has_static_permission": has_static_cap,
            "matched_static_relationship": matched_static_rel,
            "matched_transition": matched_transition,
            "static_path_id": static_path_id,
            "reason": reason,
            "is_error": is_error,
            "error_code": error_code,
            "recommendation": "Review session activity and verify identity authorization.",
            "description": (
                f"Identity '{actor}' executed '{ev_name}' against '{target}' "
                f"from IP {ev['source_ip']} (Classification: {finding_type})."
            ),
            "evidence": {
                "event_id": event_id,
                "event_time": ev["event_time"],
                "source_ip": ev["source_ip"],
                "region": ev["region"],
                "request_parameters": ev.get("request_parameters", {}),
                "matched_static_relationship": matched_static_rel,
                "matched_transition": matched_transition,
                "classification": finding_type,
                "limitations": "Observed activity consistent with telemetry; does not represent confirmed compromise."
            },
            "is_correlated": finding_type in ["CORRELATED_ACTIVITY", "OBSERVED_ATTACK_ACTIVITY"]
        }
        correlated_findings.append(finding)

    # For attack paths that were not matched, explicitly tag them as POSSIBLE_CAPABILITY
    if active_attack_paths:
        for ap in active_attack_paths:
            if ap.get("id") not in matched_path_ids:
                ap["correlation_status"] = "POSSIBLE_CAPABILITY"

    observed_attack_count = sum(1 for f in correlated_findings if f["type"] == "OBSERVED_ATTACK_ACTIVITY")
    correlated_count = sum(1 for f in correlated_findings if f["is_correlated"])
    observed_only_count = sum(1 for f in correlated_findings if f["type"] == "OBSERVED_ACTIVITY")

    metrics = {
        "static_attack_paths_count": len(active_attack_paths) if active_attack_paths else 0,
        "observed_events_count": len(normalized_events),
        "correlated_findings_count": correlated_count,
        "correlated_activity_count": correlated_count,
        "observed_activity_count": observed_only_count,
        "observed_attack_activity_count": observed_attack_count
    }

    return {
        "normalized_events": normalized_events,
        "activity_edges": activity_edges,
        "correlated_findings": correlated_findings,
        "metrics": metrics,
        "static_attack_paths_count": metrics["static_attack_paths_count"],
        "observed_events_count": metrics["observed_events_count"],
        "correlated_findings_count": metrics["correlated_findings_count"],
        "observed_attack_activity_count": metrics["observed_attack_activity_count"]
    }


class CloudTrailCorrelator:
    """Class wrapper coordinating CloudTrail event ingestion and graph correlation."""

    def normalize_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Set[str] = set()
        out: List[Dict[str, Any]] = []
        for e in events:
            eid = e.get("EventId") or e.get("event_id") or ""
            if eid:
                if eid in seen:
                    continue
                seen.add(eid)
            out.append(normalize_cloudtrail_event(e))
        return out

    def correlate_events_with_graph(self, G: nx.DiGraph, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        return correlate_activity_with_graph(events, None, G)

    def correlate_activity_with_attack_paths(
        self, attack_paths: List[Dict[str, Any]], events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        correlate_activity_with_graph(events, None, nx.DiGraph(), attack_paths)
        return attack_paths
