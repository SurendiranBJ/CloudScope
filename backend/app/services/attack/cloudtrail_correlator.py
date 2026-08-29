"""CloudTrail Security Activity Correlator.

Normalizes CloudTrail events, correlates observed runtime activity with static
IAM permissions & attack paths in the Identity Graph, records dynamic activity
relationships (e.g., ASSUMED_ROLE), and detects active lateral movement.
"""

import json
import logging
import networkx as nx
from datetime import datetime
from typing import Any, Dict, List, Optional
from app.services.scanner.inventory import AWSInventory
from app.services.graph.graph_loader import get_node_id

logger = logging.getLogger("scanner")


def normalize_cloudtrail_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw boto3 CloudTrail event into a structured security event object."""
    event_id = raw_event.get('EventId', '')
    event_name = raw_event.get('EventName', 'Unknown')
    event_time_raw = raw_event.get('EventTime')
    if isinstance(event_time_raw, datetime):
        event_time = event_time_raw.isoformat() + "Z"
    else:
        event_time = str(event_time_raw or datetime.utcnow().isoformat() + "Z")

    username = raw_event.get('Username', 'Unknown')

    # Parse nested CloudTrailEvent JSON if present
    ct_json_str = raw_event.get('CloudTrailEvent', '{}')
    ct_detail: Dict[str, Any] = {}
    if isinstance(ct_json_str, str):
        try:
            ct_detail = json.loads(ct_json_str)
        except Exception:
            ct_detail = {}
    elif isinstance(ct_json_str, dict):
        ct_detail = ct_json_str

    user_identity = ct_detail.get('userIdentity', {})
    actor_arn = user_identity.get('arn', '')
    actor_name = user_identity.get('userName') or username
    actor_type = user_identity.get('type', 'IAMUser')
    source_ip = ct_detail.get('sourceIPAddress', 'Unknown')
    region = ct_detail.get('awsRegion', raw_event.get('Region', 'global'))

    req_params = ct_detail.get('requestParameters') or {}
    target_arn = ""
    target_name = ""
    target_type = "Resource"

    # Extract event-specific target information
    if event_name == 'AssumeRole':
        target_arn = req_params.get('roleArn', '')
        if target_arn:
            target_name = target_arn.split('/')[-1]
        target_type = "Role"
    elif event_name in ['PutRolePolicy', 'AttachRolePolicy']:
        target_name = req_params.get('roleName', '')
        target_type = "Role"
    elif event_name in ['PutUserPolicy', 'AttachUserPolicy']:
        target_name = req_params.get('userName', '')
        target_type = "User"
    elif event_name in ['PutBucketPolicy', 'DeleteBucketPolicy']:
        target_name = req_params.get('bucketName', '')
        target_type = "S3"
    elif event_name == 'CreateAccessKey':
        target_name = req_params.get('userName') or actor_name
        target_type = "User"
    elif event_name == 'RunInstances':
        target_type = "EC2"
        res_list = raw_event.get('Resources', [])
        if res_list:
            target_name = res_list[0].get('ResourceName', 'EC2')

    # Fallback to resources list in raw event
    if not target_name:
        res_list = raw_event.get('Resources', [])
        if res_list:
            target_name = res_list[0].get('ResourceName', 'AWSResource')
            if ':role/' in target_name:
                target_type = "Role"
                target_name = target_name.split('/')[-1]
            elif ':user/' in target_name:
                target_type = "User"
                target_name = target_name.split('/')[-1]
            elif 's3:::' in target_name:
                target_type = "S3"
                target_name = target_name.replace('arn:aws:s3:::', '')

    # Compute risk relevance
    is_high_risk = (
        event_name in ['AssumeRole', 'PutRolePolicy', 'AttachRolePolicy', 'PutBucketPolicy', 'CreateAccessKey']
        or 'admin' in str(target_name).lower()
        or 'admin' in str(actor_name).lower()
    )

    return {
        "event_id": event_id,
        "event_name": event_name,
        "event_time": event_time,
        "actor_name": actor_name,
        "actor_arn": actor_arn,
        "actor_type": actor_type,
        "source_ip": source_ip,
        "region": region,
        "target_name": target_name,
        "target_type": target_type,
        "target_arn": target_arn,
        "is_high_risk": is_high_risk,
        "raw_details": ct_detail
    }


def correlate_activity_with_graph(
    raw_events: List[Dict[str, Any]],
    inventory: AWSInventory,
    G: nx.DiGraph
) -> Dict[str, Any]:
    """Correlate normalized CloudTrail events with graph topology.

    Returns:
        {
            "normalized_events": [...],
            "activity_edges": [...],
            "correlated_findings": [...]
        }
    """
    normalized_events = [normalize_cloudtrail_event(e) for e in raw_events]
    activity_edges: List[Dict[str, Any]] = []
    correlated_findings: List[Dict[str, Any]] = []

    user_names = {u['name'] for u in inventory.users}
    role_names = {r['name'] for r in inventory.roles}
    role_risk_map = {r['name']: r.get('riskScore', 0) for r in inventory.roles}

    for ev in normalized_events:
        actor = ev["actor_name"]
        target = ev["target_name"]
        event_name = ev["event_name"]
        event_time = ev["event_time"]
        source_ip = ev["source_ip"]
        event_id = ev["event_id"]

        if not actor or not target or actor == "Unknown":
            continue

        actor_node_id = get_node_id("User", actor) if actor in user_names else (
            get_node_id("Role", actor) if actor in role_names else None
        )
        target_node_id = get_node_id(ev["target_type"], target) if G.has_node(get_node_id(ev["target_type"], target)) else None

        if event_name == 'AssumeRole':
            target_role_node = get_node_id("Role", target)
            if actor_node_id and G.has_node(actor_node_id) and G.has_node(target_role_node):
                # 1. Record dynamic ASSUMED_ROLE edge in NetworkX
                G.add_edge(
                    actor_node_id,
                    target_role_node,
                    label='ASSUMED_ROLE',
                    timestamp=event_time,
                    eventId=event_id,
                    sourceIp=source_ip,
                    is_activity=True
                )
                activity_edges.append({
                    "source": actor_node_id,
                    "target": target_role_node,
                    "label": "ASSUMED_ROLE",
                    "timestamp": event_time,
                    "eventId": event_id,
                    "sourceIp": source_ip
                })

                # 2. Check if a static CAN_ASSUME or Attack Path exists between them
                has_static_can_assume = False
                if G.has_edge(actor_node_id, target_role_node):
                    edge_data = G.get_edge_data(actor_node_id, target_role_node, default={})
                    if edge_data.get('label') == 'CAN_ASSUME':
                        has_static_can_assume = True

                has_reachability = nx.has_path(G, actor_node_id, target_role_node)

                target_risk = role_risk_map.get(target, 0)
                is_admin_target = 'admin' in target.lower() or target_risk >= 70

                severity = "critical" if (is_admin_target or target_risk >= 60) else "high"
                score = max(85 if is_admin_target else 70, target_risk + 10)

                correlated_findings.append({
                    "id": f"corr-{event_id or hash(actor + target + event_time)}",
                    "type": "OBSERVED_ATTACK_ACTIVITY",
                    "title": f"Correlated Attack Activity: {actor} assumed {target}",
                    "actor": actor,
                    "actor_node_id": actor_node_id,
                    "target": target,
                    "target_node_id": target_role_node,
                    "target_type": "Role",
                    "event_name": "sts:AssumeRole",
                    "event_time": event_time,
                    "source_ip": source_ip,
                    "severity": severity,
                    "risk_score": min(99, score),
                    "matched_static_relationship": "CAN_ASSUME" if has_static_can_assume else ("REACHABLE_PATH" if has_reachability else "UNAUTHORIZED_TELEMETRY"),
                    "reason": f"Identity '{actor}' actively assumed privileged role '{target}' via sts:AssumeRole from source IP {source_ip}.",
                    "recommendation": f"Review whether '{actor}' requires access to '{target}'. Enforce MFA and IP constraints in the role trust policy.",
                    "is_correlated": True
                })

        elif event_name in ['PutRolePolicy', 'AttachRolePolicy', 'PutBucketPolicy', 'CreateAccessKey']:
            if actor_node_id and target_node_id:
                G.add_edge(
                    actor_node_id,
                    target_node_id,
                    label='MODIFIED_CONFIG',
                    timestamp=event_time,
                    eventId=event_id,
                    sourceIp=source_ip,
                    is_activity=True
                )
                activity_edges.append({
                    "source": actor_node_id,
                    "target": target_node_id,
                    "label": "MODIFIED_CONFIG",
                    "timestamp": event_time,
                    "eventId": event_id,
                    "sourceIp": source_ip
                })

                correlated_findings.append({
                    "id": f"corr-{event_id or hash(actor + target + event_time)}",
                    "type": "OBSERVED_CONFIG_DRIFT",
                    "title": f"Privilege Modification: {actor} executed {event_name} on {target}",
                    "actor": actor,
                    "actor_node_id": actor_node_id,
                    "target": target,
                    "target_node_id": target_node_id,
                    "target_type": ev["target_type"],
                    "event_name": event_name,
                    "event_time": event_time,
                    "source_ip": source_ip,
                    "severity": "high",
                    "risk_score": 75,
                    "matched_static_relationship": "DIRECT_MODIFICATION",
                    "reason": f"Identity '{actor}' executed policy modification action '{event_name}' affecting '{target}' from IP {source_ip}.",
                    "recommendation": f"Validate authorization for change '{event_name}' made by '{actor}'.",
                    "is_correlated": True
                })

    logger.info(
        f"CloudTrail Correlator: Processed {len(normalized_events)} events, "
        f"created {len(activity_edges)} dynamic edges, "
        f"detected {len(correlated_findings)} correlated security findings"
    )

    return {
        "normalized_events": normalized_events,
        "activity_edges": activity_edges,
        "correlated_findings": correlated_findings
    }
