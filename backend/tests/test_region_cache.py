import pytest
from unittest.mock import patch, MagicMock
from app.config import settings
from app.services.aws.region_cache import get_all_regions, clear_region_cache, set_scan_mode
import app.services.aws.region_cache as region_cache_module


# ---------------------------------------------------------------------------
# Helper to reset all module-level state between tests
# ---------------------------------------------------------------------------

def _reset_state():
    region_cache_module._scan_mode = "single"
    region_cache_module._selected_region = None
    clear_region_cache()


# ---------------------------------------------------------------------------
# Original tests (updated to reset runtime mode state before each)
# ---------------------------------------------------------------------------

def test_region_cache_default_behavior(monkeypatch):
    _reset_state()
    # Mock SCAN_REGIONS to be None/empty
    monkeypatch.setattr(settings, "SCAN_REGIONS", None)

    # When SCAN_REGIONS is empty, it should fallback to the AWS default region config or session default
    regions = get_all_regions()
    assert isinstance(regions, list)
    assert len(regions) == 1
    assert regions[0] in [settings.AWS_DEFAULT_REGION, "us-east-1", "ap-south-1"]


def test_region_cache_configured_regions(monkeypatch):
    _reset_state()
    # Mock SCAN_REGIONS with a list of regions
    monkeypatch.setattr(settings, "SCAN_REGIONS", "us-east-1,  eu-west-1,ap-south-1 ")

    regions = get_all_regions()
    assert regions == ["us-east-1", "eu-west-1", "ap-south-1"]


def test_region_cache_is_cached(monkeypatch):
    _reset_state()
    monkeypatch.setattr(settings, "SCAN_REGIONS", "us-west-2")

    regions1 = get_all_regions()
    assert regions1 == ["us-west-2"]

    # If settings change but cache is NOT cleared, it should return the cached value
    monkeypatch.setattr(settings, "SCAN_REGIONS", "us-east-1")
    regions2 = get_all_regions()
    assert regions2 == ["us-west-2"]

    # If cache IS cleared, it should return the new value
    clear_region_cache()
    regions3 = get_all_regions()
    assert regions3 == ["us-east-1"]


# ---------------------------------------------------------------------------
# New tests for runtime scan mode (set_scan_mode)
# ---------------------------------------------------------------------------

def test_set_scan_mode_single_returns_selected_region(monkeypatch):
    """set_scan_mode('single', 'eu-west-1') -> get_all_regions() returns exactly ['eu-west-1']."""
    _reset_state()
    monkeypatch.setattr(settings, "SCAN_REGIONS", None)

    set_scan_mode("single", "eu-west-1")
    regions = get_all_regions()

    assert regions == ["eu-west-1"]

    _reset_state()  # clean up after test


def test_set_scan_mode_global_returns_all_regions(monkeypatch):
    """set_scan_mode('global') -> get_all_regions() (describe_regions mocked) returns the full list."""
    _reset_state()
    monkeypatch.setattr(settings, "SCAN_REGIONS", None)

    mock_regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"]
    mock_ec2 = MagicMock()
    mock_ec2.describe_regions.return_value = {
        "Regions": [{"RegionName": r} for r in mock_regions]
    }
    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_session.client.return_value = mock_ec2

    with patch("app.services.aws.region_cache.get_aws_session", return_value=mock_session):
        set_scan_mode("global")
        regions = get_all_regions()

    assert set(regions) == set(mock_regions)
    assert len(regions) == 4

    _reset_state()


def test_default_fallback_unaffected_by_mode_logic(monkeypatch):
    """Fresh state (no runtime mode set) -> get_all_regions() falls back to session default region."""
    _reset_state()
    monkeypatch.setattr(settings, "SCAN_REGIONS", None)

    mock_session = MagicMock()
    mock_session.region_name = "ap-southeast-1"
    mock_session.profile_name = None

    with patch("app.services.aws.region_cache.get_aws_session", return_value=mock_session):
        regions = get_all_regions()

    assert regions == ["ap-southeast-1"]

    _reset_state()
