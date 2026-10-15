from app.services.ai.gemini_provider import GeminiProvider


def test_gemini_3_config_uses_supported_thinking_level_without_sampling_parameters():
    config = GeminiProvider(api_key="test-key", model="gemini-3.8-flash")._build_config("gemini-3.8-flash")

    assert config.temperature is None
    assert config.thinking_config.thinking_level.value == "LOW"
    assert config.response_mime_type == "application/json"


def test_gemini_25_fallback_keeps_legacy_thinking_budget_configuration():
    config = GeminiProvider(api_key="test-key", model="gemini-2.5-flash")._build_config("gemini-2.5-flash")

    assert config.temperature == 0.2
    assert config.thinking_config.thinking_budget == 0
