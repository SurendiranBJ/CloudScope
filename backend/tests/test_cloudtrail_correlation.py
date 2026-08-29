import json
import pytest
import networkx as nx
from datetime import datetime
from app.services.scanner.inventory import AWSInventory
from app.services.graph.graph_loader import build_local_graph
from app.services.attack.cloudtrail_correlator import (
    normalize_cloudtrail_event,
    correlate_activity_with_graph
)


def test_normalize_cloudtrail_event():
    raw_event = {
        "EventId": "evt-12345",
        "EventName": "AssumeRole",
        "EventTime": datetime(2026, 8, 29, 12, 0, 0),
        "Username": "alice",
        "CloudTrailEvent": json.dumps({
            "userIdentity": {"type": "IAMUser", "userName": "alice", "arn": "arn:aws:iam::123:user/alice"},
            "sourceIPAddress": "198.51.100.45",
            "requestParameters": {"roleArn": "arn:aws:iam::123:role/AdminRole"}
        })
    }
    norm = normalize_cloudtrail_event(raw_event)
    assert norm["event_id"] == "evt-12345"
    assert norm["event_name"] == "AssumeRole"
    assert norm["actor_name"] == "alice"
    assert norm["source_ip"] == "198.51.100.45"
    assert norm["target_name"] == "AdminRole"
    assert norm["target_type"] == "Role"
    assert norm["is_high_risk"] is True


def test_correlate_activity_with_graph_assume_role():
    inv = AWSInventory()
    inv.users = [{"id": "u1", "name": "alice", "arn": "arn:aws:iam::123:user/alice", "groups": [], "policies": []}]
    inv.roles = [{"name": "AdminRole", "arn": "arn:aws:iam::123:role/AdminRole", "trustPolicy": "{}", "attachedPolicies": [], "riskScore": 85}]

    G = build_local_graph(inv)
    assert G.has_node("aws:user:alice")
    assert G.has_node("aws:role:AdminRole")

    # Add static CAN_ASSUME edge
    G.add_edge("aws:user:alice", "aws:role:AdminRole", label="CAN_ASSUME")

    raw_events = [
        {
            "EventId": "evt-assume-001",
            "EventName": "AssumeRole",
            "EventTime": datetime(2026, 8, 29, 12, 30, 0),
            "Username": "alice",
            "CloudTrailEvent": json.dumps({
                "userIdentity": {"userName": "alice", "arn": "arn:aws:iam::123:user/alice"},
                "sourceIPAddress": "203.0.113.5",
                "requestParameters": {"roleArn": "arn:aws:iam::123:role/AdminRole"}
            })
        }
    ]

    result = correlate_activity_with_graph(raw_events, inv, G)

    # Verify dynamic activity edge
    assert G.has_edge("aws:user:alice", "aws:role:AdminRole")
    assert len(result["activity_edges"]) == 1
    assert result["activity_edges"][0]["label"] == "ASSUMED_ROLE"
    assert result["activity_edges"][0]["sourceIp"] == "203.0.113.5"

    # Verify correlated finding
    findings = result["correlated_findings"]
    assert len(findings) == 1
    assert findings[0]["type"] == "OBSERVED_ATTACK_ACTIVITY"
    assert findings[0]["actor"] == "alice"
    assert findings[0]["target"] == "AdminRole"
    assert findings[0]["severity"] == "critical"
    assert findings[0]["matched_static_relationship"] == "CAN_ASSUME"
    assert "actively assumed privileged role" in findings[0]["reason"]
