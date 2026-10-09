import pytest
from fastapi.testclient import TestClient
from unittest import mock
import os

@pytest.fixture
def prod_client():
    # Setup clean prod environment
    with mock.patch.dict(os.environ, {"ENVIRONMENT": "production", "AUTH_ENABLED": "true"}, clear=True):
        from app.config import settings
        
        # Patch the settings to be production
        with mock.patch.object(settings.__class__, 'is_production', new_callable=mock.PropertyMock) as mock_is_prod:
            mock_is_prod.return_value = True
            
            with mock.patch('app.config.settings.ENVIRONMENT', 'production'):
                with mock.patch('app.config.settings.AUTH_ENABLED', True):
                    from app.main import app
                    yield TestClient(app)

def test_pre_auth_info_disclosure(prod_client):
    """
    Asserts the ONLY 200s for unauthenticated requests in production are /live and /ready.
    Checks all openapi paths.
    """
    # Exclude openapi endpoints themselves and other swagger paths
    excluded_paths = ["/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"]
    
    app = prod_client.app
    openapi_schema = app.openapi()
    
    allowed_200_paths = ["/live", "/ready", "/api/v1/live", "/api/v1/ready"]
    
    for path, path_item in openapi_schema.get("paths", {}).items():
        if path in excluded_paths:
            continue
        
        for method in path_item.keys():
            if method.lower() == "get":
                response = prod_client.get(path)
                
                if path in allowed_200_paths:
                    assert response.status_code == 200, f"Expected {path} to be 200 OK, got {response.status_code}"
                else:
                    # Should be 401 Unauthorized, or at least not 200
                    assert response.status_code != 200, f"Information disclosure! {path} returned 200 OK unauthenticated in production."
