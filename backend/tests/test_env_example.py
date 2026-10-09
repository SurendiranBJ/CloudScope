import os
from typing import Any
import pytest
from app.config import Settings

def test_env_example_matches_config():
    # 1. Parse .env.example
    env_example_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env.example")
    
    assert os.path.exists(env_example_path), f"{env_example_path} does not exist!"
    
    env_vars = {}
    with open(env_example_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                env_vars[key.strip()] = val.strip()

    # 2. Check each key against Settings
    settings = Settings()
    settings_schema = Settings.model_fields

    for key, val in env_vars.items():
        assert key in settings_schema, f"Key {key} found in .env.example but not in app.config.Settings"
        
        # Check defaults for specific keys
        field = settings_schema[key]
        
        if key == "AWS_PROFILE":
            assert field.default == val, f"AWS_PROFILE default mismatch: .env.example has {val}, config has {field.default}"
        if key == "AWS_DEFAULT_REGION":
            assert field.default == val, f"AWS_DEFAULT_REGION default mismatch: .env.example has {val}, config has {field.default}"
        if key == "GEMINI_MODEL":
            assert field.default == val, f"GEMINI_MODEL default mismatch: .env.example has {val}, config has {field.default}"
        if key == "AI_MAX_OUTPUT_TOKENS":
            assert str(field.default) == val, f"AI_MAX_OUTPUT_TOKENS default mismatch: .env.example has {val}, config has {field.default}"
