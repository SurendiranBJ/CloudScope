"""
Integration and Unit Tests for Policies and Relationships.

Covers:
1. policies endpoint with existing cache
2. policies endpoint after cache empty (triggers scan, returns safe empty state)
3. relationships endpoint with existing cache
4. relationships endpoint after cache empty (triggers scan, returns safe empty state)
5. no duplicate scan triggered
6. group MEMBER_OF relationship
7. group HAS_POLICY relationship (authoritative scanned group policies)
8. role HAS_POLICY relationship
9. user HAS_POLICY relationship (direct & inline)
10. policy filter (all, customer-managed, aws-managed, inline)
11. relationship entity_type filter (User, Role, Group, Policy)
12. relationship search
13. entity detail endpoint (/api/v1/relationships/{entity_id})
14. duplicate relationship removal
15. no fake relationships
16. policy detail retrieval
17. invalid policy JSON does not crash frontend contract
18. API returns valid empty state when scan has no policies
19. API errors remain distinguishable from empty data
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.cache import cache
from app.services.scanner.scan_manager import scan_manager

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_state():
    cache.clear()
    scan_manager._is_running = False
    yield
    cache.clear()
    scan_manager._is_running = False


# 1. Policies endpoint with existing cache
def test_1_policies_endpoint_with_existing_cache():
    cache.set("v1:policies", [
        {
            "name": "CustomSecPolicy",
            "arn": "arn:aws:iam::123456789012:policy/CustomSecPolicy",
            "type": "customer-managed",
            "document": json.dumps({"Version": "2012-10-17", "Statement": []}),
            "riskScore": 0,
        }
    ])
    response = client.get("/api/v1/policies")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["total"] == 1
    item = data["data"]["items"][0]
    assert item["name"] == "CustomSecPolicy"
    assert item["type"] == "customer-managed"
    assert item["isAttachable"] is True
    assert "findings" in item


# 2. Policies endpoint after cache empty triggers scan
def test_2_policies_endpoint_after_cache_empty():
    assert cache.get("v1:policies") is None
    assert cache.get("v1:policy_catalog") is None

    with patch.object(scan_manager, "trigger_async_scan") as mock_scan:
        mock_scan.return_value = {"status": "TRIGGERED"}
        response = client.get("/api/v1/policies")
        assert response.status_code == 200
        mock_scan.assert_called_once()
        data = response.json()
        assert data["success"] is True
        assert data["data"]["total"] == 0
        assert data["data"]["items"] == []


# 3. Relationships endpoint with existing cache
def test_3_relationships_endpoint_with_existing_cache():
    cache.set("v1:users", [{"name": "alice", "groups": ["DevGroup"], "policies": ["ReadOnlyAccess"]}])
    cache.set("v1:groups", [{"name": "DevGroup", "attachedPolicies": ["PowerUserAccess"]}])
    cache.set("v1:roles", [{"name": "AppRole", "attachedPolicies": ["S3FullAccess"]}])
    cache.set("v1:policies", [
        {"name": "ReadOnlyAccess", "type": "aws-managed", "document": "{}"},
        {"name": "PowerUserAccess", "type": "aws-managed", "document": "{}"},
        {"name": "S3FullAccess", "type": "aws-managed", "document": "{}"},
    ])

    response = client.get("/api/v1/relationships")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["total"] >= 3
    assert data["data"]["entity_counts"]["users"] == 1
    assert data["data"]["entity_counts"]["groups"] == 1
    assert data["data"]["entity_counts"]["roles"] == 1


# 4. Relationships endpoint after cache empty triggers scan
def test_4_relationships_endpoint_after_cache_empty():
    assert cache.get("v1:users") is None
    assert cache.get("v1:roles") is None
    assert cache.get("v1:policies") is None

    with patch.object(scan_manager, "trigger_async_scan") as mock_scan:
        mock_scan.return_value = {"status": "TRIGGERED"}
        response = client.get("/api/v1/relationships")
        assert response.status_code == 200
        mock_scan.assert_called_once()
        data = response.json()
        assert data["success"] is True
        assert data["data"]["total"] == 0
        assert data["data"]["relationships"] == []


# 5. No duplicate scan triggered when scan is already running
def test_5_no_duplicate_scan_triggered():
    scan_manager._is_running = True

    with patch.object(scan_manager, "trigger_async_scan") as mock_scan:
        resp_pol = client.get("/api/v1/policies")
        assert resp_pol.status_code == 200
        mock_scan.assert_not_called()

        resp_rel = client.get("/api/v1/relationships")
        assert resp_rel.status_code == 200
        mock_scan.assert_not_called()


# 6. Group MEMBER_OF relationship
def test_6_group_member_of_relationship():
    cache.set("v1:users", [{"name": "alice", "groups": ["Admins"], "policies": []}])
    cache.set("v1:groups", [{"name": "Admins", "attachedPolicies": []}])
    cache.set("v1:roles", [])
    cache.set("v1:policies", [])

    response = client.get("/api/v1/relationships")
    assert response.status_code == 200
    rels = response.json()["data"]["relationships"]

    member_of = [r for r in rels if r["relationship"] == "MEMBER_OF"]
    assert len(member_of) == 1
    assert member_of[0]["source_id"] == "aws:user:alice"
    assert member_of[0]["target_id"] == "aws:group:Admins"
    assert member_of[0]["target_type"] == "Group"


# 7. Group HAS_POLICY relationship from authoritative scanned group inventory
def test_7_group_has_policy_relationship():
    cache.set("v1:users", [{"name": "bob", "groups": ["SecTeam"], "policies": []}])
    cache.set("v1:groups", [
        {
            "name": "SecTeam",
            "arn": "arn:aws:iam::123456789012:group/SecTeam",
            "attachedPolicies": ["SecurityAudit", "[inline] SecInline"],
        }
    ])
    cache.set("v1:roles", [])
    cache.set("v1:policies", [
        {"name": "SecurityAudit", "type": "aws-managed"},
        {"name": "SecInline", "type": "inline"},
    ])

    response = client.get("/api/v1/relationships")
    assert response.status_code == 200
    rels = response.json()["data"]["relationships"]

    group_pols = [r for r in rels if r["source_id"] == "aws:group:SecTeam" and r["relationship"] == "HAS_POLICY"]
    assert len(group_pols) == 2
    targets = {r["target_label"] for r in group_pols}
    assert "SecurityAudit" in targets
    assert "SecInline" in targets


# 8. Role HAS_POLICY relationship
def test_8_role_has_policy_relationship():
    cache.set("v1:users", [])
    cache.set("v1:groups", [])
    cache.set("v1:roles", [
        {
            "name": "EC2WorkerRole",
            "arn": "arn:aws:iam::123456789012:role/EC2WorkerRole",
            "attachedPolicies": ["AmazonS3ReadOnlyAccess"],
        }
    ])
    cache.set("v1:policies", [{"name": "AmazonS3ReadOnlyAccess", "type": "aws-managed"}])

    response = client.get("/api/v1/relationships")
    assert response.status_code == 200
    rels = response.json()["data"]["relationships"]

    role_pols = [r for r in rels if r["source_id"] == "aws:role:EC2WorkerRole" and r["relationship"] == "HAS_POLICY"]
    assert len(role_pols) == 1
    assert role_pols[0]["target_id"] == "aws:policy:AmazonS3ReadOnlyAccess"
    assert role_pols[0]["target_label"] == "AmazonS3ReadOnlyAccess"


# 9. User HAS_POLICY relationship (direct & inline)
def test_9_user_has_policy_relationship():
    cache.set("v1:users", [
        {
            "name": "dave",
            "policies": ["AdministratorAccess", "[inline] DaveInlineDoc"],
            "groups": [],
        }
    ])
    cache.set("v1:groups", [])
    cache.set("v1:roles", [])
    cache.set("v1:policies", [
        {"name": "AdministratorAccess", "type": "aws-managed"},
        {"name": "DaveInlineDoc", "type": "inline"},
    ])

    response = client.get("/api/v1/relationships")
    assert response.status_code == 200
    rels = response.json()["data"]["relationships"]

    user_pols = [r for r in rels if r["source_id"] == "aws:user:dave" and r["relationship"] == "HAS_POLICY"]
    assert len(user_pols) == 2
    targets = {r["target_label"] for r in user_pols}
    assert "AdministratorAccess" in targets
    assert "DaveInlineDoc" in targets


# 10. Policy filter
def test_10_policy_filters():
    cache.set("v1:policies", [
        {"name": "PolAWS", "arn": "arn:aws:iam::aws:policy/PolAWS", "type": "aws-managed"},
        {"name": "PolCust", "arn": "arn:aws:iam::123456789012:policy/PolCust", "type": "customer-managed"},
        {"name": "[inline] PolInl", "arn": "arn:aws:iam:inline:user:PolInl", "type": "inline"},
    ])

    # All
    r_all = client.get("/api/v1/policies").json()["data"]["items"]
    assert len(r_all) == 3

    # Customer-Managed
    r_cust = client.get("/api/v1/policies?type_filter=customer-managed").json()["data"]["items"]
    assert len(r_cust) == 1
    assert r_cust[0]["name"] == "PolCust"

    # AWS-Managed
    r_aws = client.get("/api/v1/policies?type_filter=aws-managed").json()["data"]["items"]
    assert len(r_aws) == 1
    assert r_aws[0]["name"] == "PolAWS"

    # Inline
    r_inl = client.get("/api/v1/policies?type_filter=inline").json()["data"]["items"]
    assert len(r_inl) == 1
    assert "[inline]" in r_inl[0]["name"]


# 11. Relationship entity_type filter
def test_11_relationship_entity_type_filter():
    cache.set("v1:users", [{"name": "alice", "groups": ["Admins"], "policies": []}])
    cache.set("v1:groups", [{"name": "Admins", "attachedPolicies": ["AdminPol"]}])
    cache.set("v1:roles", [{"name": "AppRole", "attachedPolicies": ["AppPol"]}])
    cache.set("v1:policies", [{"name": "AdminPol", "type": "aws-managed"}, {"name": "AppPol", "type": "aws-managed"}])

    # Filter Users
    r_users = client.get("/api/v1/relationships?entity_type=User").json()["data"]["relationships"]
    assert all(r["source_type"] == "User" or r["target_type"] == "User" for r in r_users)

    # Filter Groups
    r_groups = client.get("/api/v1/relationships?entity_type=Group").json()["data"]["relationships"]
    assert all(r["source_type"] == "Group" or r["target_type"] == "Group" for r in r_groups)

    # Filter Roles
    r_roles = client.get("/api/v1/relationships?entity_type=Role").json()["data"]["relationships"]
    assert all(r["source_type"] == "Role" or r["target_type"] == "Role" for r in r_roles)

    # Filter with non-existent type returns empty list without error
    r_none = client.get("/api/v1/relationships?entity_type=NonExistent").json()["data"]["relationships"]
    assert r_none == []


# 12. Relationship search
def test_12_relationship_search():
    cache.set("v1:users", [
        {"name": "alice_special", "groups": ["DevGroup"], "policies": []},
        {"name": "bob_regular", "groups": [], "policies": []},
    ])
    cache.set("v1:groups", [{"name": "DevGroup", "attachedPolicies": []}])
    cache.set("v1:roles", [])
    cache.set("v1:policies", [])

    r_search = client.get("/api/v1/relationships?search=special").json()["data"]["relationships"]
    assert len(r_search) == 1
    assert r_search[0]["source_label"] == "alice_special"


# 13. Entity detail endpoint
def test_13_entity_detail_endpoint():
    cache.set("v1:users", [{"name": "alice", "groups": ["Devs"], "policies": ["ReadOnly"]}])
    cache.set("v1:groups", [{"name": "Devs", "attachedPolicies": []}])
    cache.set("v1:roles", [])
    cache.set("v1:policies", [{"name": "ReadOnly", "type": "aws-managed"}])

    # Canonical ID: aws:user:alice
    res_canon = client.get("/api/v1/relationships/aws:user:alice")
    assert res_canon.status_code == 200
    data = res_canon.json()["data"]
    assert data["entity_name"] == "alice"
    assert data["entity_type"] == "User"
    assert len(data["relationships"]) == 2
    assert data["outgoing_count"] == 2

    # Type:Name: User:alice
    res_typed = client.get("/api/v1/relationships/User:alice")
    assert res_typed.status_code == 200
    assert res_typed.json()["data"]["entity_name"] == "alice"


# 14. Duplicate relationship removal
def test_14_duplicate_relationship_removal():
    # User has duplicate references in list
    cache.set("v1:users", [{"name": "alice", "groups": ["Devs", "Devs"], "policies": ["ReadOnly", "ReadOnly"]}])
    cache.set("v1:groups", [{"name": "Devs", "attachedPolicies": ["ReadOnly", "ReadOnly"]}])
    cache.set("v1:roles", [])
    cache.set("v1:policies", [{"name": "ReadOnly", "type": "aws-managed"}])

    response = client.get("/api/v1/relationships")
    assert response.status_code == 200
    rels = response.json()["data"]["relationships"]

    # Assert no duplicate (source_id, relationship, target_id)
    seen = set()
    for r in rels:
        key = (r["source_id"], r["relationship"], r["target_id"])
        assert key not in seen, f"Duplicate edge found: {key}"
        seen.add(key)


# 15. No fake relationships
def test_15_no_fake_relationships():
    cache.set("v1:users", [{"name": "isolated_user", "groups": [], "policies": []}])
    cache.set("v1:groups", [{"name": "isolated_group", "attachedPolicies": []}])
    cache.set("v1:roles", [{"name": "isolated_role", "attachedPolicies": []}])
    cache.set("v1:policies", [{"name": "isolated_pol", "type": "aws-managed"}])

    response = client.get("/api/v1/relationships")
    assert response.status_code == 200
    rels = response.json()["data"]["relationships"]
    # No edges should be created simply because entities exist
    assert len(rels) == 0


# 16. Policy detail retrieval
def test_16_policy_detail_retrieval():
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
    })
    cache.set("v1:policies", [
        {
            "name": "S3AdminPolicy",
            "arn": "arn:aws:iam::123456789012:policy/S3AdminPolicy",
            "type": "customer-managed",
            "document": policy_doc,
            "riskScore": 75,
        }
    ])
    cache.set("v1:users", [{"name": "alice", "policies": ["S3AdminPolicy"]}])

    response = client.get("/api/v1/policies/S3AdminPolicy")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["name"] == "S3AdminPolicy"
    assert data["document"] == policy_doc
    assert data["documentParsed"] is not None
    assert len(data["attachedTo"]) == 1
    assert data["attachedTo"][0]["name"] == "alice"


# 17. Invalid policy JSON does not crash backend or frontend contract
def test_17_invalid_policy_json_does_not_crash():
    cache.set("v1:policies", [
        {
            "name": "CorruptPolicy",
            "arn": "arn:aws:iam::123456789012:policy/CorruptPolicy",
            "type": "customer-managed",
            "document": "MALFORMED_NON_JSON_CONTENT{{{",
            "riskScore": 0,
        }
    ])

    response = client.get("/api/v1/policies/CorruptPolicy")
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["name"] == "CorruptPolicy"
    assert data["document"] == "MALFORMED_NON_JSON_CONTENT{{{"
    assert data["documentParsed"] is None


# 18. API returns valid empty state when scan has no policies
def test_18_api_returns_valid_empty_state_when_no_policies():
    cache.set("v1:policies", [])
    cache.set("v1:policy_catalog", [])

    response = client.get("/api/v1/policies")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["data"]["items"] == []
    assert data["data"]["total"] == 0
    assert data["data"]["total_pages"] == 1


# 19. API errors remain distinguishable from empty data
def test_19_api_errors_remain_distinguishable():
    # Calling non-existent policy detail should return 404, not 200 empty
    response = client.get("/api/v1/policies/NoSuchPolicyExists")
    assert response.status_code == 404


# 20. Snapshot A remains readable during active scan (stale-while-revalidate)
def test_20_snapshot_a_readable_during_scan():
    # Snapshot A
    cache.set("v1:policies", [{"name": "SnapshotAPolicy", "type": "aws-managed", "riskScore": 10}])
    cache.set("v1:users", [{"name": "alice_snapshot_a", "groups": [], "policies": ["SnapshotAPolicy"]}])
    cache.set("v1:groups", [])
    cache.set("v1:roles", [])

    # Simulate scan in progress
    scan_manager._is_running = True
    scan_manager._scan_status = "SCANNING"

    try:
        # GET /policies during scan must return Snapshot A
        res_policies = client.get("/api/v1/policies")
        assert res_policies.status_code == 200
        p_items = res_policies.json()["data"]["items"]
        assert len(p_items) == 1
        assert p_items[0]["name"] == "SnapshotAPolicy"

        # GET /relationships during scan must return Snapshot A
        res_rels = client.get("/api/v1/relationships")
        assert res_rels.status_code == 200
        rels = res_rels.json()["data"]["relationships"]
        assert len(rels) == 1
        assert rels[0]["source_label"] == "alice_snapshot_a"
        assert rels[0]["target_label"] == "SnapshotAPolicy"
    finally:
        scan_manager._is_running = False
        scan_manager._scan_status = "IDLE"


# 21. Snapshot B replaces Snapshot A after scan completes
def test_21_snapshot_b_replaces_snapshot_a_after_scan_success():
    # Snapshot A
    cache.set("v1:policies", [{"name": "SnapshotAPolicy", "type": "aws-managed"}])
    cache.set("v1:users", [{"name": "alice", "groups": [], "policies": ["SnapshotAPolicy"]}])

    # Scan finishes with Snapshot B
    snapshot_b = {
        "v1:policies": [{"name": "SnapshotBPolicy", "type": "customer-managed", "riskScore": 90}],
        "v1:users": [{"name": "bob", "groups": [], "policies": ["SnapshotBPolicy"]}],
        "v1:groups": [],
        "v1:roles": [],
    }
    cache.set_many(snapshot_b)
    scan_manager._scan_status = "SUCCESS"
    scan_manager._is_running = False

    res_p = client.get("/api/v1/policies")
    assert res_p.status_code == 200
    p_items = res_p.json()["data"]["items"]
    assert len(p_items) == 1
    assert p_items[0]["name"] == "SnapshotBPolicy"

    res_r = client.get("/api/v1/relationships")
    assert res_r.status_code == 200
    rels = res_r.json()["data"]["relationships"]
    assert len(rels) == 1
    assert rels[0]["source_label"] == "bob"
    assert rels[0]["target_label"] == "SnapshotBPolicy"


# 22. Failed scan preserves Snapshot A
def test_22_failed_scan_preserves_snapshot_a():
    # Snapshot A
    cache.set("v1:policies", [{"name": "PreservedPolicyA", "type": "aws-managed"}])
    cache.set("v1:users", [{"name": "charlie", "groups": [], "policies": ["PreservedPolicyA"]}])
    cache.set("v1:groups", [])
    cache.set("v1:roles", [])

    # Scan fails: snapshot is not replaced in cache
    scan_manager._is_running = False
    scan_manager._scan_status = "FAILED"
    scan_manager._last_error = "Access denied in us-east-1"

    res_p = client.get("/api/v1/policies")
    assert res_p.status_code == 200
    p_items = res_p.json()["data"]["items"]
    assert len(p_items) == 1
    assert p_items[0]["name"] == "PreservedPolicyA"

    res_r = client.get("/api/v1/relationships")
    assert res_r.status_code == 200
    rels = res_r.json()["data"]["relationships"]
    assert len(rels) == 1
    assert rels[0]["source_label"] == "charlie"


# 23. Partial scan publishes newly updated snapshot
def test_23_partial_scan_publishes_updated_snapshot():
    # Partial scan published snapshot with available data
    partial_snapshot = {
        "v1:policies": [{"name": "PartialPolicy", "type": "aws-managed", "riskScore": 40}],
        "v1:users": [{"name": "david", "groups": [], "policies": ["PartialPolicy"]}],
        "v1:groups": [],
        "v1:roles": [],
    }
    cache.set_many(partial_snapshot)
    scan_manager._scan_status = "PARTIAL"
    scan_manager._failed_regions = ["ap-south-1"]
    scan_manager._successful_regions = ["us-east-1"]

    res_p = client.get("/api/v1/policies")
    assert res_p.status_code == 200
    p_items = res_p.json()["data"]["items"]
    assert len(p_items) == 1
    assert p_items[0]["name"] == "PartialPolicy"

    res_r = client.get("/api/v1/relationships")
    assert res_r.status_code == 200
    rels = res_r.json()["data"]["relationships"]
    assert len(rels) == 1
    assert rels[0]["source_label"] == "david"

