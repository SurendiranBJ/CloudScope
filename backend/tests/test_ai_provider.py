"""
Unit tests for CloudScope AI Provider Abstraction and Gemini Provider.
All external Gemini API calls are strictly mocked.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import ValidationError

from app.services.ai.base import (
    CopilotAIResponse,
    AIAuthenticationError,
    AITimeoutError,
    AIRateLimitError,
    AIResponseValidationError,
    AIUnavailableError,
    AIConfigurationError,
)
from app.services.ai.gemini_provider import GeminiProvider
from app.services.ai.provider import get_ai_provider, reset_ai_provider
from google.genai.errors import APIError


class TestCopilotAIResponseValidation:
    """Test CopilotAIResponse schema validation rules."""

    def test_valid_structured_response(self):
        resp = CopilotAIResponse(
            summary="S3 Public Exposure Detected",
            analysis="The bucket S3-Customer-PII allows unrestricted s3:GetObject.",
            severity="HIGH",
            risk_score=78,
            affected_entities=["arn:aws:s3:::s3-customer-pii"],
            evidence=["Policy statement 'AllowPublicRead' matched action 's3:GetObject'"],
            recommendations=["Enable S3 Block Public Access"],
            suggested_questions=["Which IAM roles can write to this bucket?"],
            limitations=["Runtime CloudTrail logs cover the last 7 days."]
        )
        assert resp.summary == "S3 Public Exposure Detected"
        assert resp.severity == "HIGH"
        assert resp.risk_score == 78
        assert len(resp.affected_entities) == 1
        assert len(resp.evidence) == 1
        assert len(resp.recommendations) == 1
        assert len(resp.suggested_questions) == 1

    def test_severity_normalization(self):
        # Mixed-case or whitespace should normalize
        resp = CopilotAIResponse(
            summary="Summary",
            analysis="Analysis",
            severity="critical "
        )
        assert resp.severity == "CRITICAL"

        # Invalid severity defaults to UNKNOWN
        resp2 = CopilotAIResponse(
            summary="Summary",
            analysis="Analysis",
            severity="SUPER_EXTREME"
        )
        assert resp2.severity == "UNKNOWN"

    def test_risk_score_bounds(self):
        # None should be valid (when no authoritative risk score exists)
        resp = CopilotAIResponse(
            summary="Summary",
            analysis="Analysis",
            risk_score=None
        )
        assert resp.risk_score is None

        # 0 and 100 should be valid
        assert CopilotAIResponse(summary="S", analysis="A", risk_score=0).risk_score == 0
        assert CopilotAIResponse(summary="S", analysis="A", risk_score=100).risk_score == 100

        # Out-of-bounds risk score falls back to None via validator
        resp_invalid = CopilotAIResponse(summary="S", analysis="A", risk_score=150)
        assert resp_invalid.risk_score is None


class TestGeminiProvider:
    """Test GeminiProvider behavior with mocked Google GenAI client."""

    def test_missing_api_key_raises_auth_error(self):
        provider = GeminiProvider(api_key="")
        with pytest.raises(AIAuthenticationError) as exc_info:
            asyncio.run(provider.generate_security_response(
                prompt="Explain finding",
                security_context={"findings": []}
            ))
        assert "AI Copilot is not configured" in exc_info.value.user_friendly_message

    def test_successful_structured_generation(self):
        provider = GeminiProvider(api_key="test_key_mock")

        mock_parsed = CopilotAIResponse(
            summary="Compromised Workstation Path",
            analysis="User developer-session has direct sts:AssumeRole rights to AWSAdminRole.",
            severity="HIGH",
            risk_score=85,
            affected_entities=["developer-session", "AWSAdminRole"],
            evidence=["Trust relationship permits principal developer-session"],
            recommendations=["Attach MFA condition to assume-role trust policy"]
        )

        mock_response = MagicMock()
        mock_response.parsed = mock_parsed

        with patch.object(provider, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = asyncio.run(provider.generate_security_response(
                prompt="Analyze developer path",
                security_context={"attack_paths": [{"id": "ap-001"}]}
            ))

            assert isinstance(result, CopilotAIResponse)
            assert result.summary == "Compromised Workstation Path"
            assert result.risk_score == 85
            assert "developer-session" in result.affected_entities

    def test_json_string_parsing_and_markdown_unwrap(self):
        provider = GeminiProvider(api_key="test_key_mock")

        json_text = """```json
        {
            "summary": "Unrestricted Security Group",
            "analysis": "Security group permits 0.0.0.0/0 on port 22.",
            "severity": "CRITICAL",
            "risk_score": 90,
            "affected_entities": ["sg-0123456789"],
            "evidence": ["IpPermissions allows 0.0.0.0/0 on port 22"],
            "recommendations": ["Restrict SSH ingress to bastion CIDR"],
            "suggested_questions": ["Which EC2 instances use this security group?"],
            "limitations": []
        }
        ```"""

        mock_response = MagicMock()
        mock_response.parsed = None
        mock_response.text = json_text

        with patch.object(provider, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            result = asyncio.run(provider.generate_security_response(
                prompt="Analyze SG",
                security_context={}
            ))

            assert result.severity == "CRITICAL"
            assert result.risk_score == 90
            assert "sg-0123456789" in result.affected_entities

    def test_timeout_handling(self):
        provider = GeminiProvider(api_key="test_key_mock", timeout=1)

        async def slow_call(*args, **kwargs):
            await asyncio.sleep(2)

        with patch.object(provider, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.aio.models.generate_content = slow_call
            mock_get_client.return_value = mock_client

            with pytest.raises(AITimeoutError) as exc_info:
                asyncio.run(provider.generate_security_response(
                    prompt="Analyze something",
                    security_context={}
                ))
            assert "timed out" in exc_info.value.user_friendly_message.lower()

    def test_rate_limit_handling(self):
        provider = GeminiProvider(api_key="test_key_mock")

        api_err = APIError(429, "Resource has been exhausted (e.g. check quota)")

        with patch.object(provider, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.aio.models.generate_content = AsyncMock(side_effect=api_err)
            mock_get_client.return_value = mock_client

            with pytest.raises(AIRateLimitError):
                asyncio.run(provider.generate_security_response(
                    prompt="Analyze",
                    security_context={}
                ))

    def test_invalid_json_raises_validation_error(self):
        provider = GeminiProvider(api_key="test_key_mock")

        mock_response = MagicMock()
        mock_response.parsed = None
        mock_response.text = "This is not JSON at all."

        with patch.object(provider, "_get_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
            mock_get_client.return_value = mock_client

            with pytest.raises(AIResponseValidationError):
                asyncio.run(provider.generate_security_response(
                    prompt="Analyze",
                    security_context={}
                ))


class TestProviderFactory:
    """Test get_ai_provider and configuration loading."""

    def test_default_gemini_provider(self):
        reset_ai_provider()
        provider = get_ai_provider("gemini")
        assert isinstance(provider, GeminiProvider)

    def test_unsupported_provider_raises_config_error(self):
        with pytest.raises(AIConfigurationError):
            get_ai_provider("unsupported_provider_xyz")
