"""
CloudScope CloudTrail Security Activity Correlator.

Normalizes CloudTrail events, maps exact runtime activity types (ASSUMED_ROLE,
MODIFIED_POLICY, CREATED_ACCESS_KEY, ACCESSED_RESOURCE, SECURITY_EVENT),
synchronizes activity idempotently into Neo4j using eventId, and correlates
observed events with static graph attack paths.
"""

import json
import logging
import networkx as nx
from datetime import datetime
from typing import Any, Dict, List, Optional
from app.database import execute_write
from app.services.scanner.inventory import AWSInventory
from app.services.graph.graph_loader import get_node_id

logger = logging.getLogger("scanner")


def get_activity_type(event_name: str) -> str:
    """Classify the exact security activity relationship type from AWS event name."""
    if event_name == "AssumeRole":
        return "ASSUMED_ROLE"
    if event_name in [
        "PutRolePolicy", "AttachRolePolicy", "PutUserPolicy", "AttachUserPolicy",
        "PutGroupPolicy", "AttachGroupPolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion"
    ]:
        return "MODIFIED_POLICY"
    if event_name in ["CreateAccessKey", "CreateLoginProfile"]:
        return "CREATED_ACCESS_KEY"
    if event_name in [
        "GetObject", "PutObject", "DeleteObject", "GetSecretValue",
        "DescribeDBInstances", "RunInstances", "Invoke"
    ]:
        return "ACCESSED_RESOURCE"
    return "SECURITY_EVENT"


def normalize_cloudtrail_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw boto3 CloudTrail event into a structured security event object."""
    event_id = raw_event.get('EventId', '') or raw_event.get('event_id', '')
    event_name = raw_event.get('EventName', 'Unknown') or raw_event.get('event_name', 'Unknown')
    event_time_raw = raw_event.get('EventTime') or raw_event.get('event_time')
    
    if isinstance(event_time_raw, datetime):
        event_time = event_time_raw.isoformat() + "Z"
    else:
        event_time = str(event_time_raw or datetime.utcnow().isoformat() + "Z")

    username = raw_event.get('Username') or raw_event.get('username') or 'Unknown'

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
    source_ip = ct_detail.get('sourceIPAddress', raw_event.get('source_ip', 'Unknown'))
    region = ct_detail.get('awsRegion', raw_event.get('region', 'global'))

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

    activity_type = get_activity_type(event_name)
    is_high_risk = activity_type in ["ASSUMED_ROLE", "MODIFIED_POLICY", "CREATED_ACCESS_KEY"]

    return {
        "event_id": event_id,
        "event_name": event_name,
        "activity_type": activity_type,
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


def sync_activity_into_neo4j(normalized_events: List[Dict[str, Any]]):
    """Write normalized CloudTrail events into Neo4j using idempotent MERGE on eventId."""
    for ev in normalized_events:
        event_id = ev["event_id"]
        if not event_id:
            continue

        actor_name = ev["actor_name"]
        target_name = ev["target_name"]
        activity_type = ev["activity_type"]

        actor_node_id = get_node_id("User", actor_name)
        target_node_id = get_node_id(ev["target_type"], target_name) if target_name else None

        try:
            # 1. Create ActivityEvent node (Idempotent by eventId)
            execute_write(
                """
                MERGE (a:ActivityEvent {eventId: $eventId})
                SET a.eventName = $eventName,
                    a.activityType = $activityType,
                    a.timestamp = $timestamp,
                    a.sourceIp = $sourceIp,
                    a.region = $region,
                    a.actor = $actor,
                    a.target = $target
                """,
                {
                    "eventId": event_id,
                    "eventName": ev["event_name"],
                    "activityType": activity_type,
                    "timestamp": ev["event_time"],
                    "sourceIp": ev["source_ip"],
                    "region": ev["region"],
                    "actor": actor_name,
                    "target": target_name or "N/A"
                }
            )

            # 2. If actor and target exist in graph, write dynamic activity edge
            if target_node_id and target_name:
                execute_write(
                    f"""
                    MATCH (u:User {{id: $actor_id}}), (tgt {{id: $target_id}})
                    MERGE (u)-[r:{activity_type} {{eventId: $eventId}}]->(tgt)
                    SET r.timestamp = $timestamp,
                        r.sourceIp = $sourceIp,
                        r.eventName = $eventName
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
    raw_events: List[Dict[str, Any]],
    inventory: AWSInventory,
    G: nx.DiGraph
) -> Dict[str, Any]:
    """Correlate normalized CloudTrail events with graph topology."""
    normalized_events = [normalize_cloudtrail_event(e) for e in raw_events]
    
    # Sync activity into Neo4j idempotently
    sync_activity_into_neo4j(normalized_events)

    activity_edges: List[Dict[str, Any]] = []
    correlated_findings: List[Dict[str, Any]] = []

    user_names = {u['name'] for u in inventory.users}
    role_names = {r['name'] for r in inventory.roles}
    role_risk_map = {r['name']: r.get('riskScore', 0) for r in inventory.roles}

    for ev in normalized_events:
        actor = ev["actor_name"]
        target = ev["target_name"]
        ev_name = ev["event_name"]
        act_type = ev["activity_type"]

        if not actor or actor == "Unknown":
            continue

        actor_node_id = get_node_id("User", actor)

        # Activity on Role
        if target and target in role_names:
            target_node_id = get_node_id("Role", target)

            # Check if static CAN_ASSUME edge exists in NetworkX
            has_static_edge = G.has_edge(actor_node_id, target_node_id) if G else False
            target_risk = role_risk_map.get(target, 0)

            finding_type = "OBSERVED_ATTACK_ACTIVITY" if (has_static_edge or target_risk >= 50) else "OBSERVED_ACTIVITY"
            severity = "critical" if target_risk >= 80 else ("high" if target_risk >= 60 else "medium")

            finding = {
                "id": f"corr-{ev['event_id']}",
                "type": finding_type,
                "finding_type": finding_type,
                "event_id": ev["event_id"],
                "actor": actor,
                "target": target,
                "event_name": ev_name,
                "activity_type": act_type,
                "timestamp": ev["event_time"],
                "source_ip": ev["source_ip"],
                "severity": severity,
                "target_risk_score": target_risk,
                "has_static_permission": has_static_edge,
                "description": (
                    f"Identity '{actor}' executed '{ev_name}' against role '{target}' "
                    f"from IP {ev['source_ip']} (Static permission: {'Verified' if has_static_edge else 'Unmapped'})."
                )
            }
            correlated_findings.append(finding)

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

            # Also add to NetworkX graph so paths can traverse dynamic activity
            if G and G.has_node(actor_node_id) and G.has_node(target_node_id):
                G.add_edge(
                    actor_node_id,
                    target_node_id,
                    label=act_type,
                    type=act_type,
                    eventId=ev["event_id"],
                    timestamp=ev["event_time"]
                )

    return {
        "normalized_events": normalized_events,
        "activity_edges": activity_edges,
        "correlated_findings": correlated_findings
    }
