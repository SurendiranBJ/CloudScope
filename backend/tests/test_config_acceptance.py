import os
from unittest import mock
import pytest
from fastapi.testclient import TestClient

@pytest.fixture
def mock_env_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("ENVIRONMENT=production\nAUTH_ENABLED=true\nAUTH_REQUIRED=true\nDEV_AUTH_MODE=false\n")
    return str(env_file)

def test_production_auth_acceptance(mock_env_file):
    # Ensure clean environment
    with mock.patch.dict(os.environ, clear=True):
        from pydantic_settings import SettingsConfigDict
        from app.config import Settings
        
        # Create a Settings instance that reads from the mock env file
        class TestSettings(Settings):
            model_config = SettingsConfigDict(env_file=mock_env_file, env_file_encoding="utf-8", extra="ignore")

        test_settings = TestSettings()
        
        assert test_settings.ENVIRONMENT == "production"
        assert test_settings.AUTH_ENABLED is True
        assert test_settings.AUTH_REQUIRED is True
        
        # Patch the global settings with our test settings
        with mock.patch('app.config.settings', test_settings):
            # Now load app (so dependencies get the patched settings)
            from app.main import app
            
            client = TestClient(app)
            
            # Make an unauthenticated request to an endpoint that requires auth
            response = client.get("/api/v1/health/aws")
            
            # It should be 401 Unauthorized
            assert response.status_code == 401, f"Expected 401, got {response.status_code}: {response.text}"
