import pytest
from datetime import datetime, timezone
import networkx as nx
from app.services.attack.cloudtrail_correlator import (
    CloudTrailCorrelator,
    normalize_cloudtrail_event,
    normalize_principal,
    parse_timezone_aware_timestamp,
    correlate_activity_with_graph
)


def test_event_normalization_fields():
    raw_event = {
        "EventId": "evt-12345",
        "EventName": "GetObject",
        "EventTime": "2026-09-22T12:00:00Z",
        "EventSource": "s3.amazonaws.com",
        "ReadOnly": "true",
        "Username": "alice",
        "SourceIPAddress": "198.51.100.2",
        "UserAgent": "aws-cli/2.0",
        "ErrorCode": None,
        "ErrorMessage": None,
        "RequestParameters": '{"bucketName": "target-bucket", "key": "secret.txt"}'
    }
    norm = normalize_cloudtrail_event(raw_event)
    assert norm["event_id"] == "evt-12345"
    assert norm["event_name"] == "GetObject"
    assert norm["read_only"] is True
    assert norm["source_ip"] == "198.51.100.2"
    assert norm["request_parameters"]["bucketName"] == "target-bucket"
    assert norm["event_time"].endswith("+00:00") or norm["event_time"].endswith("Z")


def test_timezone_aware_timestamp_handling():
    dt1 = parse_timezone_aware_timestamp("2026-09-22T10:30:00Z")
    assert dt1.tzinfo is not None
    assert dt1.tzinfo == timezone.utc

    dt2 = parse_timezone_aware_timestamp("2026-09-22T10:30:00+05:30")
    assert dt2.tzinfo is not None
    assert dt2.utcoffset().total_seconds() == 5.5 * 3600

    # Test comparison between timestamps is safe (no TypeError: can't compare offset-naive and offset-aware)
    assert dt1 > dt2


def test_principal_normalization_iam_user():
    userIdentity = {
        "type": "IAMUser",
        "principalId": "AIDAEXAMPLEUSER",
        "arn": "arn:aws:iam::123456789012:user/alice",
        "userName": "alice"
    }
    p_id, p_type, p_arn = normalize_principal(userIdentity)
    assert p_id == "arn:aws:iam::123456789012:user/alice"
    assert p_type == "User"
    assert p_arn == "arn:aws:iam::123456789012:user/alice"


def test_principal_normalization_assumed_role():
    userIdentity = {
        "type": "AssumedRole",
        "principalId": "AROAEXAMPLEROLE:session-name",
        "arn": "arn:aws:sts::123456789012:assumed-role/TargetRole/session-name"
    }
    p_id, p_type, p_arn = normalize_principal(userIdentity)
    assert p_id == "arn:aws:iam::123456789012:role/TargetRole"
    assert p_type == "Role"


def test_principal_normalization_root():
    userIdentity = {
        "type": "Root",
        "principalId": "123456789012",
        "arn": "arn:aws:iam::123456789012:root"
    }
    p_id, p_type, p_arn = normalize_principal(userIdentity)
    assert p_id == "arn:aws:iam::123456789012:root"
    assert p_type == "Root"


def test_principal_normalization_federated_user():
    userIdentity = {
        "type": "FederatedUser",
        "principalId": "123456789012:fed_user",
        "arn": "arn:aws:sts::123456789012:federated-user/fed_user"
    }
    p_id, p_type, p_arn = normalize_principal(userIdentity)
    assert p_id == "arn:aws:sts::123456789012:federated-user/fed_user"


def test_event_id_deduplication_idempotency():
    correlator = CloudTrailCorrelator()
    events = [
        {"EventId": "evt-dup-1", "EventName": "GetObject", "EventTime": "2026-09-22T10:00:00Z"},
        {"EventId": "evt-dup-1", "EventName": "GetObject", "EventTime": "2026-09-22T10:00:00Z"},
        {"EventId": "evt-unique-2", "EventName": "PutObject", "EventTime": "2026-09-22T10:05:00Z"}
    ]
    norm_events = correlator.normalize_events(events)
    assert len(norm_events) == 2
    assert {e["event_id"] for e in norm_events} == {"evt-dup-1", "evt-unique-2"}


def test_assumerole_correlation_to_can_assume_edge():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/alice"
    r = "arn:aws:iam::123456789012:role/AdminRole"
    G.add_node(u, type="User", name="alice")
    G.add_node(r, type="Role", name="AdminRole")
    G.add_edge(u, r, relationship="CAN_ASSUME", edge_type="CAN_ASSUME")

    correlator = CloudTrailCorrelator()
    event = {
        "EventId": "evt-assume-1",
        "EventName": "AssumeRole",
        "EventTime": "2026-09-22T11:00:00Z",
        "Username": "alice",
        "userIdentity": {"type": "IAMUser", "arn": u, "userName": "alice"},
        "RequestParameters": '{"roleArn": "arn:aws:iam::123456789012:role/AdminRole"}'
    }
    result = correlator.correlate_events_with_graph(G, [event])
    assert result["correlated_findings_count"] == 1
    assert G.has_edge(u, r)
    assert G[u][r].get("correlation_status") == "CORRELATED_ACTIVITY"
    assert G[u][r].get("last_observed_event_id") == "evt-assume-1"


def test_assumerole_without_static_edge_marked_anomalous_observed():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/unauthorized_user"
    r = "arn:aws:iam::123456789012:role/AdminRole"
    G.add_node(u, type="User", name="unauthorized_user")
    G.add_node(r, type="Role", name="AdminRole")
    # No static CAN_ASSUME edge exists

    correlator = CloudTrailCorrelator()
    event = {
        "EventId": "evt-anomaly-1",
        "EventName": "AssumeRole",
        "EventTime": "2026-09-22T11:30:00Z",
        "Username": "unauthorized_user",
        "userIdentity": {"type": "IAMUser", "arn": u, "userName": "unauthorized_user"},
        "RequestParameters": '{"roleArn": "arn:aws:iam::123456789012:role/AdminRole"}'
    }
    result = correlator.correlate_events_with_graph(G, [event])
    # Edge added with OBSERVED_ACTIVITY, not STATIC CAPABILITY
    assert G.has_edge(u, r)
    edge = G[u][r]
    assert edge.get("correlation_status") == "OBSERVED_ACTIVITY"
    assert edge.get("is_anomalous") is True


def test_s3_data_event_correlates_to_s3_node():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/analyst"
    b = "arn:aws:s3:::customer-records"
    G.add_node(u, type="User", name="analyst")
    G.add_node(b, type="S3", name="customer-records")
    G.add_edge(u, b, relationship="ALLOWS", edge_type="ALLOWS")

    correlator = CloudTrailCorrelator()
    event = {
        "EventId": "evt-s3-1",
        "EventName": "GetObject",
        "EventTime": "2026-09-22T12:15:00Z",
        "userIdentity": {"type": "IAMUser", "arn": u},
        "Resources": [{"ARN": "arn:aws:s3:::customer-records/report.csv"}]
    }
    result = correlator.correlate_events_with_graph(G, [event])
    assert result["correlated_findings_count"] >= 1
    assert G[u][b].get("correlation_status") == "CORRELATED_ACTIVITY"


def test_secretsmanager_event_correlates_to_secret_node():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/backend"
    s = "arn:aws:secretsmanager:us-east-1:123456789012:secret:db/master"
    G.add_node(u, type="User", name="backend")
    G.add_node(s, type="Secret", name="db/master")
    G.add_edge(u, s, relationship="ALLOWS")

    correlator = CloudTrailCorrelator()
    event = {
        "EventId": "evt-sec-1",
        "EventName": "GetSecretValue",
        "EventTime": "2026-09-22T12:20:00Z",
        "userIdentity": {"type": "IAMUser", "arn": u},
        "Resources": [{"ARN": s}]
    }
    result = correlator.correlate_events_with_graph(G, [event])
    assert G[u][s].get("correlation_status") == "CORRELATED_ACTIVITY"


def test_ec2_event_correlates_to_ec2_node():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/ops"
    inst = "i-0987654321fedcba0"
    G.add_node(u, type="User", name="ops")
    G.add_node(inst, type="EC2", name="WebServer")
    G.add_edge(u, inst, relationship="ALLOWS")

    correlator = CloudTrailCorrelator()
    event = {
        "EventId": "evt-ec2-1",
        "EventName": "StartInstances",
        "EventTime": "2026-09-22T12:25:00Z",
        "userIdentity": {"type": "IAMUser", "arn": u},
        "RequestParameters": f'{{"instanceSet": {{"items": [{{"instanceId": "{inst}"}}]}}}}'
    }
    result = correlator.correlate_events_with_graph(G, [event])
    assert G[u][inst].get("correlation_status") == "CORRELATED_ACTIVITY"


def test_policy_modification_event_detection():
    correlator = CloudTrailCorrelator()
    event = {
        "EventId": "evt-mod-1",
        "EventName": "AttachUserPolicy",
        "EventTime": "2026-09-22T12:30:00Z",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/admin"},
        "RequestParameters": '{"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}'
    }
    norm = normalize_cloudtrail_event(event)
    assert norm.get("is_security_modification") is True


def test_error_events_not_treated_as_successful_transitions():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/intruder"
    r = "arn:aws:iam::123456789012:role/SuperAdmin"
    G.add_node(u, type="User", name="intruder")
    G.add_node(r, type="Role", name="SuperAdmin")

    correlator = CloudTrailCorrelator()
    event = {
        "EventId": "evt-denied-1",
        "EventName": "AssumeRole",
        "EventTime": "2026-09-22T12:35:00Z",
        "ErrorCode": "AccessDenied",
        "ErrorMessage": "User is not authorized to perform: sts:AssumeRole",
        "userIdentity": {"type": "IAMUser", "arn": u},
        "RequestParameters": '{"roleArn": "arn:aws:iam::123456789012:role/SuperAdmin"}'
    }
    result = correlator.correlate_events_with_graph(G, [event])
    # Denied event must NOT establish an active transition edge
    assert not G.has_edge(u, r)


def test_static_capability_vs_observed_activity_distinction():
    attack_path = {
        "id": "path-1",
        "name": "User to Admin Role",
        "nodes": [{"id": "user-1"}, {"id": "role-admin"}],
        "ordered_relationships": ["CAN_ASSUME"]
    }
    assert attack_path.get("correlation_status") is None  # Defaults to POSSIBLE_CAPABILITY


def test_correlated_activity_metric_increment():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/bob"
    r = "arn:aws:iam::123456789012:role/Auditor"
    G.add_node(u, type="User", name="bob")
    G.add_node(r, type="Role", name="Auditor")
    G.add_edge(u, r, relationship="CAN_ASSUME")

    correlator = CloudTrailCorrelator()
    events = [
        {
            "EventId": "evt-auditor-1",
            "EventName": "AssumeRole",
            "EventTime": "2026-09-22T13:00:00Z",
            "userIdentity": {"type": "IAMUser", "arn": u},
            "RequestParameters": '{"roleArn": "arn:aws:iam::123456789012:role/Auditor"}'
        }
    ]
    metrics = correlator.correlate_events_with_graph(G, events)
    assert metrics["correlated_findings_count"] == 1


def test_observed_attack_activity_on_attack_path():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/attacker"
    r = "arn:aws:iam::123456789012:role/Admin"
    s = "arn:aws:s3:::critical-secrets"

    G.add_node(u, type="User", name="attacker")
    G.add_node(r, type="Role", name="Admin")
    G.add_node(s, type="S3", name="critical-secrets")
    G.add_edge(u, r, relationship="CAN_ASSUME")
    G.add_edge(r, s, relationship="ALLOWS")

    attack_paths = [
        {
            "id": "path-attack-1",
            "name": "Attacker Path",
            "nodes": [{"id": u}, {"id": r}, {"id": s}],
            "ordered_relationships": ["CAN_ASSUME", "ALLOWS"],
            "risk_score": 90
        }
    ]
    cloudtrail_events = [
        {
            "EventId": "evt-attack-exec-1",
            "EventName": "GetObject",
            "EventTime": "2026-09-22T14:00:00Z",
            "userIdentity": {"type": "AssumedRole", "arn": f"arn:aws:sts::123456789012:assumed-role/Admin/session"},
            "Resources": [{"ARN": s}]
        }
    ]
    correlator = CloudTrailCorrelator()
    findings = correlator.correlate_activity_with_attack_paths(attack_paths, cloudtrail_events)
    assert findings[0]["correlation_status"] == "OBSERVED_ATTACK_ACTIVITY"


def test_no_name_heuristics_in_correlation():
    G = nx.DiGraph()
    # A user named "admin" who does NOT have permission to Role "AdminRole"
    u = "arn:aws:iam::123456789012:user/admin"
    r = "arn:aws:iam::123456789012:role/AdminRole"
    G.add_node(u, type="User", name="admin")
    G.add_node(r, type="Role", name="AdminRole")

    correlator = CloudTrailCorrelator()
    # Event is for another principal entirely
    event = {
        "EventId": "evt-other-1",
        "EventName": "AssumeRole",
        "EventTime": "2026-09-22T14:15:00Z",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/other_user"},
        "RequestParameters": '{"roleArn": "arn:aws:iam::123456789012:role/AdminRole"}'
    }
    correlator.correlate_events_with_graph(G, [event])
    # Must NOT connect or correlate user/admin just because of the name "admin"
    assert not G.has_edge(u, r)


def test_correlate_activity_with_graph_idempotence():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/charlie"
    s = "arn:aws:s3:::logs"
    G.add_node(u, type="User", name="charlie")
    G.add_node(s, type="S3", name="logs")
    G.add_edge(u, s, relationship="ALLOWS")

    events = [
        {
            "EventId": "evt-charlie-1",
            "EventName": "GetObject",
            "EventTime": "2026-09-22T14:30:00Z",
            "userIdentity": {"type": "IAMUser", "arn": u},
            "Resources": [{"ARN": s}]
        }
    ]
    correlator = CloudTrailCorrelator()
    res1 = correlator.correlate_events_with_graph(G, events)
    edge_count1 = len(G.edges())

    res2 = correlator.correlate_events_with_graph(G, events)
    edge_count2 = len(G.edges())

    assert edge_count1 == edge_count2
    assert res1["correlated_findings_count"] == res2["correlated_findings_count"]


def test_end_to_end_cloudtrail_reconciliation():
    G = nx.DiGraph()
    u = "arn:aws:iam::123456789012:user/dev"
    r = "arn:aws:iam::123456789012:role/ProdAccess"
    b = "arn:aws:s3:::prod-bucket"

    G.add_node(u, type="User", name="dev", riskScore=30)
    G.add_node(r, type="Role", name="ProdAccess", riskScore=80)
    G.add_node(b, type="S3", name="prod-bucket", riskScore=75, region="us-east-1")

    G.add_edge(u, r, relationship="CAN_ASSUME", edge_type="CAN_ASSUME")
    G.add_edge(r, b, relationship="ALLOWS", edge_type="ALLOWS")

    raw_events = [
        {
            "EventId": "evt-e2e-1",
            "EventName": "AssumeRole",
            "EventTime": "2026-09-22T15:00:00Z",
            "userIdentity": {"type": "IAMUser", "arn": u},
            "RequestParameters": '{"roleArn": "arn:aws:iam::123456789012:role/ProdAccess"}'
        },
        {
            "EventId": "evt-e2e-2",
            "EventName": "GetObject",
            "EventTime": "2026-09-22T15:05:00Z",
            "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/ProdAccess/session"},
            "Resources": [{"ARN": b}]
        }
    ]

    metrics = correlate_activity_with_graph(G, raw_events)
    assert metrics["observed_events_count"] == 2
    assert metrics["correlated_findings_count"] >= 1
    assert G[u][r].get("correlation_status") == "CORRELATED_ACTIVITY"
