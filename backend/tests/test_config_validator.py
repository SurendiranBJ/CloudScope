import os
import pytest
from app.security.config_validator import validate_configuration, is_placeholder

@pytest.fixture
def prod_env(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    # Base secure config
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    monkeypatch.setenv("DEV_AUTH_MODE", "false")
    monkeypatch.setenv("JWT_SECRET", "this-is-a-very-secure-secret-that-is-at-least-32-chars!")
    monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
    monkeypatch.setenv("OIDC_AUDIENCE", "cloudscope-prod")
    monkeypatch.setenv("NEO4J_PASSWORD", "strong-neo4j-password-12345!")

def test_placeholder_detector():
    assert is_placeholder("replace-with-secure-password")
    assert is_placeholder("changeme")
    assert is_placeholder("example-only")
    assert is_placeholder("password")
    assert not is_placeholder("this-is-a-very-secure-secret-that-is-at-least-32-chars!")

def test_valid_production_config(prod_env):
    valid, issues = validate_configuration()
    assert valid is True
    assert len(issues) == 0

def test_missing_production_values_rejected(prod_env, monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("OIDC_ISSUER_URL", raising=False)
    valid, issues = validate_configuration()
    assert valid is False
    assert any("Production requires OIDC_JWKS_URL or a strong JWT_SECRET" in i for i in issues)
    assert any("OIDC_ISSUER_URL is required in production" in i for i in issues)

def test_placeholder_secrets_rejected(prod_env, monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "replace-with-secure-password-that-is-at-least-32-chars!")
    monkeypatch.setenv("NEO4J_PASSWORD", "changeme")
    valid, issues = validate_configuration()
    assert valid is False
    assert any("placeholder JWT_SECRET" in i for i in issues)
    assert any("Insecure default NEO4J_PASSWORD" in i for i in issues)

def test_weak_known_defaults_rejected(prod_env, monkeypatch):
    monkeypatch.setenv("NEO4J_PASSWORD", "password")
    valid, issues = validate_configuration()
    assert valid is False
    assert any("Insecure default NEO4J_PASSWORD" in i for i in issues)

def test_dev_auth_mode_rejected_in_production(prod_env, monkeypatch):
    monkeypatch.setenv("DEV_AUTH_MODE", "true")
    valid, issues = validate_configuration()
    assert valid is False
    assert any("DEV_AUTH_MODE=true is strictly prohibited in production" in i for i in issues)

def test_production_authentication_remains_mandatory(prod_env, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "false")
    valid, issues = validate_configuration()
    assert valid is False
    assert any("AUTH_REQUIRED must be true in production" in i for i in issues)
