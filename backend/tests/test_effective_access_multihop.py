import json
from unittest.mock import MagicMock
import pytest

from app.services.simulation.effective_access import compute_effective_access, compute_reachable_resources


def test_multihop_role_assumption_effective_access():
    """
    Test Phase 3 & 4:
    User -> CAN_ASSUME -> RoleA -> CAN_ASSUME -> RoleB -> Policy -> S3AssetA
    Ensure User effectively reaches S3AssetA with exact provenance and correct relationship sequence.
    Also ensure duplicates are deduplicated in blast radius calculations.
    """
    users = [{
        "name": "alice",
        "arn": "arn:aws:iam::123456789012:user/alice",
        "policies": ["AssumeRoleAPolicy"],
        "attachedPolicies": [],
        "groups": []
    }]

    roles = [
        {
            "name": "RoleA",
            "arn": "arn:aws:iam::123456789012:role/RoleA",
            "trustPolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                    "Action": "sts:AssumeRole"
                }]
            }),
            "attachedPolicies": ["AssumeRoleBPolicy"],
            "attachedPolicyArns": {},
            "inlinePolicyDocuments": {}
        },
        {
            "name": "RoleB",
            "arn": "arn:aws:iam::123456789012:role/RoleB",
            "trustPolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/RoleA"},
                    "Action": "sts:AssumeRole"
                }]
            }),
            "attachedPolicies": ["S3AccessPolicy"],
            "attachedPolicyArns": {},
            "inlinePolicyDocuments": {}
        }
    ]

    policy_doc_map = {
        "AssumeRoleAPolicy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123456789012:role/RoleA"
            }]
        }),
        "AssumeRoleBPolicy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123456789012:role/RoleB"
            }]
        }),
        "S3AccessPolicy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::confidential-bucket/*"
            }]
        })
    }

    all_resources = [
        {
            "id": "s3-confidential",
            "name": "confidential-bucket",
            "arn": "arn:aws:s3:::confidential-bucket",
            "type": "S3"
        }
    ]

    inventory = MagicMock()
    inventory.users = users
    inventory.roles = roles
    inventory.groups = []

    records = compute_effective_access(inventory, policy_doc_map, all_resources)

    # Alice reaches confidential-bucket via RoleA -> RoleB -> S3AccessPolicy -> confidential-bucket
    alice_records = [r for r in records if r["identity_name"] == "alice"]
    assert len(alice_records) == 1
    rec = alice_records[0]

    assert rec["target_resource_name"] == "confidential-bucket"
    assert rec["access_path"] == ["alice", "RoleA", "RoleB", "S3AccessPolicy", "confidential-bucket"]
    assert rec["through_relationship"] == ["CAN_ASSUME", "CAN_ASSUME", "HAS_POLICY", "ALLOWS"]


def test_role_cycle_protection():
    """
    Test Phase 3 Q:
    RoleA -> CAN_ASSUME -> RoleB -> CAN_ASSUME -> RoleA (cycle)
    Ensure traversal terminates deterministically without infinite loops.
    """
    roles = [
        {
            "name": "RoleA",
            "arn": "arn:aws:iam::123456789012:role/RoleA",
            "trustPolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/RoleB"},
                    "Action": "sts:AssumeRole"
                }]
            }),
            "attachedPolicies": ["AssumeRoleBPolicy"],
            "attachedPolicyArns": {},
            "inlinePolicyDocuments": {}
        },
        {
            "name": "RoleB",
            "arn": "arn:aws:iam::123456789012:role/RoleB",
            "trustPolicy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/RoleA"},
                    "Action": "sts:AssumeRole"
                }]
            }),
            "attachedPolicies": ["AssumeRoleAPolicy"],
            "attachedPolicyArns": {},
            "inlinePolicyDocuments": {}
        }
    ]

    policy_doc_map = {
        "AssumeRoleAPolicy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123456789012:role/RoleA"
            }]
        }),
        "AssumeRoleBPolicy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123456789012:role/RoleB"
            }]
        })
    }

    inventory = MagicMock()
    inventory.users = []
    inventory.roles = roles
    inventory.groups = []

    # Must complete quickly without recursion error or timeout
    records = compute_effective_access(inventory, policy_doc_map, [])
    assert isinstance(records, list)


def test_unique_asset_blast_radius_deduplication():
    """
    Test Phase 4:
    User -> RoleA -> Policy -> S3-A
    User -> RoleA -> Policy -> S3-A
    User -> RoleA -> Policy -> S3-B
    Must count exactly 2 unique cloud assets, not 3.
    """
    users = [{
        "name": "bob",
        "arn": "arn:aws:iam::123456789012:user/bob",
        "policies": ["MultiPolicy"],
        "attachedPolicies": [],
        "groups": []
    }]

    policy_doc_map = {
        "MultiPolicy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket-a/*"},
                {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::bucket-a/*"},
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket-b/*"},
            ]
        })
    }

    all_resources = [
        {"id": "bucket-a", "name": "bucket-a", "type": "S3"},
        {"id": "bucket-b", "name": "bucket-b", "type": "S3"}
    ]

    inventory = MagicMock()
    inventory.users = users
    inventory.roles = []
    inventory.groups = []

    reach = compute_reachable_resources(inventory, policy_doc_map, all_resources)
    bob_reach = reach.get("User:bob", set())
    assert len(bob_reach) == 2
    assert bob_reach == {"bucket-a", "bucket-b"}
