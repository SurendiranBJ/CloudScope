from datetime import datetime, timedelta, timezone

from app.persistence.database import get_db_session
from app.persistence.models import CloudProjectModel
from app.services.aws import session as aws_session


def test_assumed_role_credentials_refresh_before_expiration(monkeypatch, request):
    request.addfinalizer(aws_session._assumed_role_credentials.clear)
    project = CloudProjectModel(
        project_id="refresh-project",
        owner_issuer="https://issuer.test",
        owner_subject="refresh-owner",
        name="Refresh test",
        description="",
        account_id="123456789012",
        role_arn="arn:aws:iam::123456789012:role/CloudScopeReadOnly",
        external_id="unique-external-id",
        verification_status="CONNECTED",
        status="ACTIVE",
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        created_by="test",
    )
    with get_db_session() as db:
        db.add(project)

    assume_role_calls = []

    class FakeSts:
        def assume_role(self, **kwargs):
            assume_role_calls.append(kwargs)
            now = datetime.now(timezone.utc)
            expiry = now + (timedelta(minutes=1) if len(assume_role_calls) == 1 else timedelta(hours=1))
            return {
                "Credentials": {
                    "AccessKeyId": f"temporary-key-{len(assume_role_calls)}",
                    "SecretAccessKey": "temporary-secret",
                    "SessionToken": "temporary-token",
                    "Expiration": expiry,
                }
            }

        def get_caller_identity(self):
            return {"Account": "123456789012"}

    class FakeSession:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def client(self, service_name, **kwargs):
            assert service_name == "sts"
            return FakeSts()

    real_boto3_session = aws_session.boto3.Session

    def make_boto3_session(**kwargs):
        if "botocore_session" in kwargs:
            return real_boto3_session(**kwargs)
        return FakeSession(**kwargs)

    monkeypatch.setattr(aws_session.boto3, "Session", make_boto3_session)
    monkeypatch.setattr(aws_session.settings, "AWS_PROFILE", "test-profile")
    aws_session._assumed_role_credentials.clear()

    session = aws_session._get_project_aws_session("refresh-project", "us-east-1")
    frozen = session.get_credentials().get_frozen_credentials()

    assert frozen.access_key == "temporary-key-2"
    assert len(assume_role_calls) == 2
    assert all(call["ExternalId"] == "unique-external-id" for call in assume_role_calls)
