from datetime import datetime, timezone

from app.services.aws import extended_resources_service


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_kwargs):
        return iter(self.pages)


class FakeKmsClient:
    def __init__(self):
        self.policy_requests = []

    def get_paginator(self, operation):
        pages = {
            "list_keys": [{"Keys": [{"KeyId": "aws-key"}, {"KeyId": "customer-key"}]}],
            "list_aliases": [{"Aliases": [
                {"AliasName": "alias/aws/s3", "TargetKeyId": "aws-key"},
                {"AliasName": "alias/customer-data", "TargetKeyId": "customer-key"},
            ]}],
        }
        return FakePaginator(pages[operation])

    def describe_key(self, *, KeyId):
        base = {
            "Arn": f"arn:aws:kms:ap-south-1:123456789012:key/{KeyId}",
            "AWSAccountId": "123456789012",
            "KeyState": "Enabled" if KeyId == "aws-key" else "PendingDeletion",
            "Enabled": KeyId == "aws-key",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeySpec": "SYMMETRIC_DEFAULT",
            "Origin": "AWS_KMS",
            "MultiRegion": False,
            "KeyManager": "AWS" if KeyId == "aws-key" else "CUSTOMER",
            "Description": "Customer key description" if KeyId == "customer-key" else "",
        }
        if KeyId == "customer-key":
            base["DeletionDate"] = datetime(2026, 11, 12, tzinfo=timezone.utc)
        return {"KeyMetadata": base}

    def get_key_policy(self, *, KeyId, PolicyName):
        self.policy_requests.append((KeyId, PolicyName))
        return {"Policy": '{"Statement":[]}'}


class FakeSession:
    def __init__(self):
        self.kms_client = FakeKmsClient()

    def client(self, service, **_kwargs):
        if service == "kms":
            return self.kms_client
        operations = {
            "sqs": "list_queues",
            "sns": "list_topics",
            "eks": "list_clusters",
            "stepfunctions": "list_state_machines",
        }
        return FakeEmptyClient(operations[service])


class FakeEmptyClient:
    def __init__(self, operation):
        self.operation = operation

    def get_paginator(self, operation):
        return FakePaginator([{}])


def test_kms_inventory_includes_aws_and_customer_managed_keys_with_console_metadata(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(extended_resources_service, "get_all_regions", lambda: ["ap-south-1"])
    monkeypatch.setattr(extended_resources_service, "make_region_sessions", lambda _regions: {"ap-south-1": session})

    collected = extended_resources_service.collect_messaging_and_workflow_resources()

    keys = collected["KMS"].items
    assert len(keys) == 2
    by_manager = {key["details"]["key_manager"]: key for key in keys}
    assert set(by_manager) == {"AWS", "CUSTOMER"}

    aws_key = by_manager["AWS"]
    assert aws_key["name"] == "alias/aws/s3"
    assert aws_key["details"]["key_manager_label"] == "AWS-managed"
    assert aws_key["details"]["resource_policy_status"] == "AWS_MANAGED_KEY_POLICY"
    assert aws_key["region"] == "ap-south-1"

    customer_key = by_manager["CUSTOMER"]
    assert customer_key["name"] == "alias/customer-data"
    assert customer_key["details"]["key_state"] == "PendingDeletion"
    assert customer_key["details"]["enabled"] is False
    assert customer_key["details"]["deletion_date"] == "2026-11-12T00:00:00+00:00"
    assert customer_key["details"]["resource_policy_status"] == "COLLECTED"
    assert session.kms_client.policy_requests == [("customer-key", "default")]
