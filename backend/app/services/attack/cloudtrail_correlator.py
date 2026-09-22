"""
CloudScope CloudTrail Security Activity Correlator.

Normalizes CloudTrail events, maps exact runtime activity types (ASSUMED_ROLE,
MODIFIED_POLICY, CREATED_ACCESS_KEY, ACCESSED_RESOURCE, SECURITY_EVENT),
synchronizes activity idempotently into Neo4j using eventId, and correlates
observed runtime events with static graph capabilities and attack paths.

Enforces clear semantic distinction:
- POSSIBLE_CAPABILITY (Static analysis: what an identity can potentially do)
- OBSERVED_ACTIVITY (CloudTrail: what activity actually occurred)
- CORRELATED_ACTIVITY (Observed activity matching a static capability)
- OBSERVED_ATTACK_ACTIVITY (Observed activity consistent with an identified attack path)
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
    "Invoke": "ACCESSED_RESOURCE",
}


def get_activity_type(event_name: str) -> str:
    """Classify the exact security activity relationship type from AWS event name."""
    return SECURITY_EVENT_TYPES.get(event_name, "SECURITY_EVENT")


def parse_timezone_aware_timestamp(event_time_raw: Any) -> datetime:
    """Parse raw timestamp into a standardized timezone-aware datetime object."""
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
            pass
    return datetime.now(timezone.utc)


def normalize_principal(identity_input: Any) -> Tuple[str, str, str]:
    """Normalize principal identity to (principal_id, principal_type, principal_arn)."""
    if isinstance(identity_input, str):
        arn = identity_input
        if ":user/" in arn:
            return arn, "User", arn
        elif ":role/" in arn:
            return arn, "Role", arn
        elif ":assumed-role/" in arn:
            parts = arn.split(":assumed-role/")[1].split("/")
            role_name = parts[0]
            acc = arn.split(":")[4]
            base_arn = f"arn:aws:iam::{acc}:role/{role_name}"
            return base_arn, "Role", base_arn
        elif ":root" in arn:
            return arn, "Root", arn
        return arn, "Principal", arn
    elif isinstance(identity_input, dict):
        p_type = identity_input.get("type", "IAMUser")
        arn = identity_input.get("arn", "")
        p_id = identity_input.get("principalId", "")
        user_name = identity_input.get("userName", "")

        if p_type == "IAMUser":
            norm_arn = arn or (f"arn:aws:iam::123456789012:user/{user_name}" if user_name else p_id)
            return norm_arn, "User", norm_arn
        elif p_type == "AssumedRole":
            if ":assumed-role/" in arn:
                parts = arn.split(":assumed-role/")[1].split("/")
                role_name = parts[0]
                acc = arn.split(":")[4]
                base_arn = f"arn:aws:iam::{acc}:role/{role_name}"
                return base_arn, "Role", base_arn
            elif ":role/" in arn:
                return arn, "Role", arn
            return arn or p_id, "Role", arn or p_id
        elif p_type == "Root":
            norm_arn = arn or "arn:aws:iam::123456789012:root"
            return norm_arn, "Root", norm_arn
        elif p_type == "FederatedUser":
            return arn or p_id, "FederatedUser", arn or p_id
        return arn or p_id, p_type, arn or p_id
    return str(identity_input), "Unknown", str(identity_input)


def normalize_cloudtrail_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw boto3 or dictionary CloudTrail event into a structured security event object."""
    event_id = raw_event.get('EventId', '') or raw_event.get('event_id', '') or ''
    event_name = raw_event.get('EventName', 'Unknown') or raw_event.get('event_name', 'Unknown')
    event_time_raw = raw_event.get('EventTime') or raw_event.get('event_time')
    dt = parse_timezone_aware_timestamp(event_time_raw)
    event_time = dt.isoformat()

    username = raw_event.get('Username') or raw_event.get('username') or 'Unknown'

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
    Preserves historical activity nodes and dynamic edges.
    """
    for ev in normalized_events:
        event_id = ev["event_id"]
        if not event_id:
            continue

        actor_name = ev["actor_name"]
        target_name = ev["target_name"]
        activity_type = ev["activity_type"]

        actor_node_id = map_principal_to_node_id(actor_name, ev.get("actor_arn", ""), ev.get("actor_type", "IAMUser"))
        target_node_id = get_node_id(ev["target_type"], target_name) if target_name else None

        try:
            # 1. Create ActivityEvent node (Idempotent MERGE by eventId)
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
                    "timestamp": ev["event_time"],
                    "sourceIp": ev["source_ip"],
                    "region": ev["region"],
                    "actor": actor_name,
                    "target": target_name or "N/A",
                    "userAgent": ev.get("user_agent", ""),
                    "accountId": ev.get("account_id", "")
                }
            )

            # 2. Dynamic activity edge (Idempotent MERGE by eventId)
            if target_node_id and target_name:
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
                        "timestamp": ev["event_time"],
                        "sourceIp": ev["source_ip"],
                        "eventName": ev["event_name"]
                    }
                )
        except Exception as e:
            logger.debug(f"Could not record activity in Neo4j for event {event_id}: {e}")


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
    - OBSERVED_ATTACK_ACTIVITY: event matches an identified attack path transition
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

    user_names = {u.get('name', '') for u in getattr(real_inventory, 'users', [])}
    role_names = {r.get('name', '') for r in getattr(real_inventory, 'roles', [])}
    role_risk_map = {r.get('name', ''): r.get('riskScore', 0) for r in getattr(real_inventory, 'roles', [])}

    # Pre-index attack paths for exact transition matching
    attack_path_transitions: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    attack_path_targets: Dict[str, List[Dict[str, Any]]] = {}
    if attack_paths:
        for ap in attack_paths:
            nodes = ap.get("nodes") or ap.get("ordered_nodes") or []
            rels = ap.get("orderedRelationships") or ap.get("ordered_relationships") or []
            tgt = ap.get("target") or ap.get("destination", "")
            if tgt:
                attack_path_targets.setdefault(tgt, []).append(ap)
            for i in range(len(rels)):
                if i + 1 < len(nodes):
                    u_n = nodes[i].get("name") or nodes[i].get("id")
                    v_n = nodes[i+1].get("name") or nodes[i+1].get("id")
                    r_l = rels[i]
                    attack_path_transitions.setdefault((u_n, v_n, r_l), []).append(ap)

    matched_path_ids: Set[str] = set()

    for ev in normalized_events:
        # Error events (e.g., AccessDenied) must not be treated as successful transitions
        if ev.get("error_code") in ["AccessDenied", "ClientUnauthorized", "UnauthorizedOperation"]:
            continue

        actor = ev["actor_name"]
        target = ev["target_name"]
        ev_name = ev["event_name"]
        act_type = ev["activity_type"]
        actor_type = ev["actor_type"]
        actor_arn = ev.get("actor_arn", "")
        target_arn = ev.get("target_arn", "")

        if not actor or actor == "Unknown":
            continue

        actor_node_id = map_principal_to_node_id(actor, actor_arn, actor_type)
        target_node_id = get_node_id(ev["target_type"], target) if target else None

        # Check if static graph has this edge across various ID forms (ARN, node_id, name)
        possible_sources = [s for s in [actor_arn, actor_node_id, actor] if s]
        if ":assumed-role/" in actor_arn:
            try:
                acc = actor_arn.split(":")[4]
                base_role_arn = f"arn:aws:iam::{acc}:role/{actor}"
                possible_sources.append(base_role_arn)
            except Exception:
                pass

        possible_targets = [t for t in [target_arn, target_node_id, target] if t]
        
        # Also check resources in event for S3/Secrets/EC2
        for r_entry in ev.get("resources", []):
            r_arn = r_entry.get("ARN") or r_entry.get("ResourceName", "")
            if r_arn:
                possible_targets.append(r_arn)
                if "/" in r_arn and "arn:aws:s3:::" in r_arn:
                    # add bucket root
                    possible_targets.append(r_arn.split("/")[0])

        has_static_edge = False
        matched_edge_src = None
        matched_edge_tgt = None

        if real_G:
            for s in possible_sources:
                if real_G.has_node(s):
                    for t in possible_targets:
                        if real_G.has_node(t) and real_G.has_edge(s, t):
                            has_static_edge = True
                            matched_edge_src = s
                            matched_edge_tgt = t
                            break
                    if has_static_edge:
                        break

        target_risk = role_risk_map.get(target, 0)

        # Check if matches an identified attack path transition
        matching_paths = []
        for s in possible_sources:
            for t in possible_targets:
                if (s, t, "CAN_ASSUME") in attack_path_transitions:
                    matching_paths.extend(attack_path_transitions[(s, t, "CAN_ASSUME")])
                elif (s, t, "ALLOWS") in attack_path_transitions:
                    matching_paths.extend(attack_path_transitions[(s, t, "ALLOWS")])
                if t in attack_path_targets:
                    matching_paths.extend(attack_path_targets[t])

        if attack_paths:
            # Also check if event actor or target is in attack path nodes
            for ap in attack_paths:
                ap_nodes = []
                for n in ap.get("nodes", []):
                    nid = n.get("id") or n.get("name") or ""
                    if nid:
                        ap_nodes.append(nid)
                        if "/" in nid:
                            ap_nodes.append(nid.split("/")[-1])
                actor_matches = any(s in ap_nodes for s in possible_sources)
                target_matches = any(t in ap_nodes for t in possible_targets)
                if actor_matches and target_matches:
                    if ap not in matching_paths:
                        matching_paths.append(ap)

        if matching_paths:
            finding_type = "OBSERVED_ATTACK_ACTIVITY"
            matched_static_rel = "CAN_ASSUME" if act_type == "ASSUMED_ROLE" else act_type
            static_path_id = matching_paths[0].get("id", "path-unknown")
            matched_path_ids.add(static_path_id)
            matching_paths[0]["correlation_status"] = "OBSERVED_ATTACK_ACTIVITY"
            matching_paths[0].setdefault("observed_activity", []).append(ev)

            reason = (
                f"Observed activity consistent with identified attack path '{static_path_id}': "
                f"principal '{actor}' executed '{ev_name}' against target '{target}'."
            )
        elif has_static_edge or (target and (target in role_names or target in user_names)):
            finding_type = "CORRELATED_ACTIVITY"
            matched_static_rel = "CAN_ASSUME" if has_static_edge else "MAPPED_IDENTITY"
            static_path_id = None
            reason = (
                f"Observed activity matches verified static IAM authorization in the security graph: "
                f"'{actor}' executed '{ev_name}' against '{target}'."
            )
            # Update edge in real_G
            if matched_edge_src and matched_edge_tgt and real_G.has_edge(matched_edge_src, matched_edge_tgt):
                real_G[matched_edge_src][matched_edge_tgt]["correlation_status"] = "CORRELATED_ACTIVITY"
                real_G[matched_edge_src][matched_edge_tgt]["last_observed_event_id"] = ev["event_id"]
        else:
            finding_type = "OBSERVED_ACTIVITY"
            matched_static_rel = "NONE"
            static_path_id = None
            reason = f"Observed CloudTrail management event '{ev_name}' executed by '{actor}'."

            # If AssumeRole was observed without static permission, create anomalous edge
            if act_type == "ASSUMED_ROLE" and real_G:
                s_node = actor_arn if real_G.has_node(actor_arn) else (actor_node_id if real_G.has_node(actor_node_id) else actor)
                t_node = target_arn if real_G.has_node(target_arn) else (target_node_id if real_G.has_node(target_node_id) else target)
                if real_G.has_node(s_node) and real_G.has_node(t_node):
                    real_G.add_edge(
                        s_node,
                        t_node,
                        relationship="ASSUMED_ROLE",
                        correlation_status="OBSERVED_ACTIVITY",
                        is_anomalous=True,
                        eventId=ev["event_id"],
                        last_observed_event_id=ev["event_id"]
                    )

        severity = "critical" if (target_risk >= 80 or finding_type == "OBSERVED_ATTACK_ACTIVITY") else ("high" if target_risk >= 60 else "medium")

        finding = {
            "id": f"corr-{ev['event_id']}",
            "type": finding_type,
            "finding_type": finding_type,
            "title": f"Observed {ev_name} Activity by {actor}",
            "actor": actor,
            "principal": ev.get("principal", actor),
            "actor_node_id": actor_node_id,
            "target": target or "N/A",
            "target_node_id": target_node_id,
            "target_type": ev["target_type"],
            "event_id": ev["event_id"],
            "event_name": ev_name,
            "event_time": ev["event_time"],
            "timestamp": ev["event_time"],
            "activity_type": act_type,
            "source_ip": ev["source_ip"],
            "region": ev["region"],
            "aws_region": ev["aws_region"],
            "user_agent": ev["user_agent"],
            "severity": severity,
            "risk_score": max(target_risk, 30 if finding_type == "OBSERVED_ATTACK_ACTIVITY" else 15),
            "target_risk_score": target_risk,
            "has_static_permission": has_static_edge,
            "matched_static_relationship": matched_static_rel,
            "static_path_id": static_path_id,
            "reason": reason,
            "recommendation": "Review session activity and verify identity authorization.",
            "description": (
                f"Identity '{actor}' executed '{ev_name}' against '{target}' "
                f"from IP {ev['source_ip']} (Classification: {finding_type})."
            ),
            "evidence": {
                "event_id": ev["event_id"],
                "event_time": ev["event_time"],
                "source_ip": ev["source_ip"],
                "region": ev["region"],
                "request_parameters": ev.get("request_parameters", {}),
                "matched_static_relationship": matched_static_rel,
                "classification": finding_type,
                "limitations": "Observed activity consistent with telemetry; does not represent confirmed compromise."
            },
            "is_correlated": finding_type in ["CORRELATED_ACTIVITY", "OBSERVED_ATTACK_ACTIVITY"]
        }
        correlated_findings.append(finding)

        if target_node_id:
            activity_edges.append({
                "source": actor_node_id,
                "target": target_node_id,
                "label": act_type,
                "type": act_type,
                "event_id": ev["event_id"],
                "timestamp": ev["event_time"],
                "sourceIp": ev["source_ip"],
                "source_ip": ev["source_ip"],
                "is_active": True
            })

            if real_G and real_G.has_node(actor_node_id) and real_G.has_node(target_node_id):
                real_G.add_edge(
                    actor_node_id,
                    target_node_id,
                    label=act_type,
                    type=act_type,
                    eventId=ev["event_id"],
                    timestamp=ev["event_time"],
                    is_activity=True
                )

    # For attack paths that were not matched, explicitly tag them as POSSIBLE_CAPABILITY
    if attack_paths:
        for ap in attack_paths:
            if ap.get("id") not in matched_path_ids:
                ap["correlation_status"] = "POSSIBLE_CAPABILITY"

    observed_attack_count = sum(1 for f in correlated_findings if f["type"] == "OBSERVED_ATTACK_ACTIVITY")
    correlated_count = sum(1 for f in correlated_findings if f["is_correlated"])

    metrics = {
        "static_attack_paths_count": len(attack_paths) if attack_paths else 0,
        "observed_events_count": len(normalized_events),
        "correlated_findings_count": correlated_count,
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

