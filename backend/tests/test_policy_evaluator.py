import json
import pytest
from app.services.attack.policy_evaluator import (
    parse_policy_document,
    match_action,
    match_resource_arn,
    evaluate_policy_allows_resources,
    evaluate_assume_role_trust,
    evaluate_policy_document_risk,
    evaluate_trust_policy_risk
)


def test_parse_policy_document():
    doc = {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
    }
    stmts = parse_policy_document(doc)
    assert len(stmts) == 1
    assert stmts[0]["Effect"] == "Allow"
    assert stmts[0]["Action"] == ["s3:GetObject"]
    assert stmts[0]["Resource"] == ["arn:aws:s3:::my-bucket/*"]


def test_wildcard_action_and_resource():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    resources = [
        {"id": "b1", "name": "bucket-one", "type": "S3", "arn": "arn:aws:s3:::bucket-one"},
        {"id": "sec1", "name": "db-secret", "type": "Secrets", "arn": "arn:aws:secretsmanager:ap-south-1:123:secret:db-secret"},
        {"id": "rds1", "name": "db-prod", "type": "RDS", "arn": "arn:aws:rds:ap-south-1:123:db:db-prod"}
    ]
    matched = evaluate_policy_allows_resources(doc, resources)
    assert len(matched) == 3


def test_specific_s3_bucket_arn_matching():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::target-bucket/*"
            }
        ]
    }
    resources = [
        {"id": "b1", "name": "target-bucket", "type": "S3", "arn": "arn:aws:s3:::target-bucket"},
        {"id": "b2", "name": "other-bucket", "type": "S3", "arn": "arn:aws:s3:::other-bucket"}
    ]
    matched = evaluate_policy_allows_resources(doc, resources)
    assert len(matched) == 1
    assert matched[0]["name"] == "target-bucket"


def test_explicit_deny_overrides_allow():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::confidential-bucket/*"
            }
        ]
    }
    resources = [
        {"id": "b1", "name": "confidential-bucket", "type": "S3", "arn": "arn:aws:s3:::confidential-bucket"},
        {"id": "b2", "name": "public-bucket", "type": "S3", "arn": "arn:aws:s3:::public-bucket"}
    ]
    matched = evaluate_policy_allows_resources(doc, resources)
    assert len(matched) == 1
    assert matched[0]["name"] == "public-bucket"


def test_secrets_manager_arn_matching():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "arn:aws:secretsmanager:ap-south-1:123456789012:secret:production-database-*"
            }
        ]
    }
    resources = [
        {"id": "s1", "name": "production-database", "type": "Secrets", "arn": "arn:aws:secretsmanager:ap-south-1:123456789012:secret:production-database-aBcDe"},
        {"id": "s2", "name": "staging-database", "type": "Secrets", "arn": "arn:aws:secretsmanager:ap-south-1:123456789012:secret:staging-database-xYz"}
    ]
    matched = evaluate_policy_allows_resources(doc, resources)
    assert len(matched) == 1
    assert matched[0]["name"] == "production-database"


def test_evaluate_assume_role_trust_wildcard():
    trust_doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    users = [{"id": "u1", "name": "alice", "arn": "arn:aws:iam::123:user/alice"}]
    roles = [
        {"name": "AdminRole", "arn": "arn:aws:iam::123:role/AdminRole"},
        {"name": "DevRole", "arn": "arn:aws:iam::123:role/DevRole"}
    ]
    result = evaluate_assume_role_trust(trust_doc, "AdminRole", users, roles, "123")
    assert len(result["users"]) == 1
    assert result["users"][0]["name"] == "alice"
    assert len(result["roles"]) == 1
    assert result["roles"][0]["name"] == "DevRole"


def test_evaluate_assume_role_trust_specific_user():
    trust_doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123:user/bob"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    users = [
        {"id": "u1", "name": "alice", "arn": "arn:aws:iam::123:user/alice"},
        {"id": "u2", "name": "bob", "arn": "arn:aws:iam::123:user/bob"}
    ]
    roles = [{"name": "AdminRole", "arn": "arn:aws:iam::123:role/AdminRole"}]
    result = evaluate_assume_role_trust(trust_doc, "AdminRole", users, roles, "123")
    assert len(result["users"]) == 1
    assert result["users"][0]["name"] == "bob"
