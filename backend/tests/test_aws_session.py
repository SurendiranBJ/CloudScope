import pytest
from unittest.mock import MagicMock, patch
from app.services.aws.session import get_aws_diagnostic_info, get_aws_session, get_account_id


def test_get_aws_diagnostic_info_success():
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:user/scanner",
        "UserId": "AIDA12345EXAMPLE"
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_sts
    mock_session.region_name = "ap-south-1"

    with patch("app.services.aws.session.get_aws_session", return_value=mock_session):
        diag = get_aws_diagnostic_info()
        assert diag["authenticated"] is True
        assert diag["account_id"] == "123456789012"
        assert diag["arn"] == "arn:aws:iam::123456789012:user/scanner"
        assert diag["user_id"] == "AIDA12345EXAMPLE"
        assert diag["region"] == "ap-south-1"
        assert diag["error"] is None


def test_get_aws_diagnostic_info_failure():
    with patch("app.services.aws.session.get_aws_session", side_effect=Exception("No credentials found")):
        diag = get_aws_diagnostic_info()
        assert diag["authenticated"] is False
        assert diag["account_id"] is None
        assert "No credentials" in diag["error"]
