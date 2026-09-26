"""
CloudScope AI Provider Factory.

Instantiates and returns the configured AI provider implementation based on settings.
"""

import logging
from typing import Optional
from app.config import settings
from app.services.ai.base import AIProvider, AIConfigurationError
from app.services.ai.gemini_provider import GeminiProvider

logger = logging.getLogger("backend")

_provider_instance: Optional[AIProvider] = None


def get_ai_provider(provider_type: Optional[str] = None) -> AIProvider:
    """
    Factory function to retrieve the configured AIProvider instance.
    Defaults to settings.AI_PROVIDER (e.g., 'gemini').
    """
    global _provider_instance
    chosen_provider = (provider_type or settings.AI_PROVIDER or "gemini").lower()

    if chosen_provider == "gemini":
        if _provider_instance is None or not isinstance(_provider_instance, GeminiProvider):
            _provider_instance = GeminiProvider()
        return _provider_instance
    else:
        raise AIConfigurationError(
            f"Unsupported AI provider: '{chosen_provider}'. Supported: 'gemini'",
            user_friendly_message=f"Configured AI provider '{chosen_provider}' is not supported."
        )


def reset_ai_provider():
    """Reset provider singleton (primarily for testing and reconfiguration)."""
    global _provider_instance
    _provider_instance = None
