"""
CloudScope AI Provider Base Models and Protocol.
"""

from typing import Protocol, List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, field_validator


class CopilotAIResponse(BaseModel):
    """
    Validated structured AI response for CloudScope Security Copilot.
    Grounds all analysis, risk scores, and affected entities strictly in authoritative evidence.
    """
    summary: str
    analysis: str
    severity: Optional[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]] = None
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    affected_entities: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    suggested_questions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip().upper()
        if s in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}:
            return s
        return "UNKNOWN"

    @field_validator("risk_score", mode="before")
    @classmethod
    def validate_risk_score(cls, v: Any) -> Optional[int]:
        if v is None or v == "":
            return None
        try:
            val = int(v)
            if 0 <= val <= 100:
                return val
            return None
        except (ValueError, TypeError):
            return None


class AIProviderError(Exception):
    """Base exception for AI provider operations."""
    def __init__(self, message: str, user_friendly_message: Optional[str] = None):
        super().__init__(message)
        self.user_friendly_message = user_friendly_message or message


class AIConfigurationError(AIProviderError):
    """Raised when AI configuration is missing or invalid."""
    pass


class AIAuthenticationError(AIProviderError):
    """Raised when AI credentials/API keys are invalid or missing."""
    pass


class AITimeoutError(AIProviderError):
    """Raised when an AI provider call times out."""
    pass


class AIRateLimitError(AIProviderError):
    """Raised when rate limits or quotas are exceeded."""
    pass


class AIResponseValidationError(AIProviderError):
    """Raised when the AI model returns output that fails schema validation."""
    pass


class AIUnavailableError(AIProviderError):
    """Raised when AI provider service is down or unreachable."""
    pass


class AIProvider(Protocol):
    """
    Protocol for AI providers.
    The router interacts ONLY through this interface and knows no SDK-specific details.
    """
    async def generate_security_response(
        self,
        prompt: str,
        security_context: Dict[str, Any],
        system_instructions: Optional[str] = None
    ) -> CopilotAIResponse:
        """Generate an evidence-grounded security response."""
        ...
