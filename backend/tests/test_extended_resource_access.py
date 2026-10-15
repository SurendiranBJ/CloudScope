import json

from app.services.attack.policy_evaluator import (
    evaluate_policy_allows_resources,
    evaluate_resource_policy_grants,
)
from app.services.attack.risk_engine import get_resource_risk_assessment


def test_iam_policy_evaluation_supports_new_aws_service_actions():
    resources = [
        {"id": "queue-arn", "name": "orders", "type": "SQS", "arn": "arn:aws:sqs:us-east-1:123456789012:orders"},
        {"id": "machine-arn", "name": "workflow", "type": "StepFunctions", "arn": "arn:aws:states:us-east-1:123456789012:stateMachine:workflow"},
        {"id": "key-arn", "name": "data-key", "type": "KMS", "arn": "arn:aws:kms:us-east-1:123456789012:key/abc", "details": {
            "resource_policy_status": "COLLECTED",
            "resource_policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:Decrypt", "Resource": "*"}]}),
        }},
    ]
    doc = {"Statement": [
        {"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": resources[0]["arn"]},
        {"Effect": "Allow", "Action": "states:StartExecution", "Resource": resources[1]["arn"]},
        {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": resources[2]["arn"]},
    ]}

    assert {item["type"] for item in evaluate_policy_allows_resources(doc, resources, account_id="123456789012")} == {"SQS", "StepFunctions", "KMS"}


def test_kms_identity_policy_is_not_effective_without_key_policy_delegation():
    key = {"id": "key-arn", "name": "data-key", "type": "KMS", "arn": "arn:aws:kms:us-east-1:123456789012:key/abc", "details": {
        "resource_policy_status": "COLLECTED",
        "resource_policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/Other"}, "Action": "kms:Decrypt", "Resource": "*"}]}),
    }}
    identity_policy = {"Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key["arn"]}]}

    assert evaluate_policy_allows_resources(identity_policy, [key], account_id="123456789012") == []


def test_resource_policy_grants_only_exact_known_aws_principals():
    user_arn = "arn:aws:iam::123456789012:user/alice"
    outside_arn = "arn:aws:iam::210987654321:user/bob"
    resource = {
        "id": "orders", "name": "orders", "type": "SQS",
        "arn": "arn:aws:sqs:us-east-1:123456789012:orders",
        "details": {
            "resource_policy_status": "COLLECTED",
            "resource_policy": json.dumps({"Statement": [
                {"Effect": "Allow", "Principal": {"AWS": user_arn}, "Action": "sqs:ReceiveMessage", "Resource": "*"},
                {"Effect": "Allow", "Principal": {"AWS": outside_arn}, "Action": "sqs:SendMessage", "Resource": "*"},
                {"Effect": "Allow", "Principal": "*", "Action": "sqs:*", "Resource": "*"},
            ]}),
        },
    }
    principals = [
        {"name": "alice", "arn": user_arn, "type": "User"},
        {"name": "bob", "arn": outside_arn, "type": "User"},
    ]

    grants = evaluate_resource_policy_grants(resource, principals, "123456789012")
    assert [(grant["principal"]["name"], grant["action"]) for grant in grants] == [("alice", "sqs:ReceiveMessage")]


def test_resource_policy_with_unresolved_runtime_condition_is_not_reported_as_grant():
    user_arn = "arn:aws:iam::123456789012:user/alice"
    resource = {
        "id": "reports", "name": "reports", "type": "S3", "arn": "arn:aws:s3:::reports",
        "details": {
            "resource_policy_status": "COLLECTED",
            "resource_policy": json.dumps({"Statement": [{
                "Effect": "Allow", "Principal": {"AWS": user_arn},
                "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            }]}),
        },
    }

    assert evaluate_resource_policy_grants(resource, [{"name": "alice", "arn": user_arn}], "123456789012") == []


def test_resource_policy_explicit_deny_overrides_allow_for_same_principal():
    user_arn = "arn:aws:iam::123456789012:user/alice"
    resource = {
        "id": "reports", "name": "reports", "type": "S3", "arn": "arn:aws:s3:::reports",
        "details": {
            "resource_policy_status": "COLLECTED",
            "resource_policy": json.dumps({"Statement": [
                {"Effect": "Allow", "Principal": {"AWS": user_arn}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"},
                {"Effect": "Deny", "Principal": {"AWS": user_arn}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"},
            ]}),
        },
    }

    assert evaluate_resource_policy_grants(resource, [{"name": "alice", "arn": user_arn}], "123456789012") == []


def test_unconditional_public_resource_policy_is_reported_as_risk():
    resource = {
        "id": "orders", "name": "orders", "type": "SQS", "arn": "arn:aws:sqs:us-east-1:123456789012:orders",
        "details": {"resource_policy": json.dumps({"Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "sqs:ReceiveMessage", "Resource": "*",
        }]})},
    }

    assessment = get_resource_risk_assessment(resource)
    assert assessment["score"] >= 45
    assert any(factor["code"] == "PUBLIC_RESOURCE_POLICY" for factor in assessment["factors"])
