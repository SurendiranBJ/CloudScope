import pytest
from app.config import settings
from app.services.aws.region_cache import get_all_regions, clear_region_cache

def test_region_cache_default_behavior(monkeypatch):
    clear_region_cache()
    # Mock SCAN_REGIONS to be None/empty
    monkeypatch.setattr(settings, "SCAN_REGIONS", None)
    
    # When SCAN_REGIONS is empty, it should fallback to the AWS default region config or session default
    regions = get_all_regions()
    assert isinstance(regions, list)
    assert len(regions) == 1
    assert regions[0] in [settings.AWS_DEFAULT_REGION, "us-east-1", "ap-south-1"]

def test_region_cache_configured_regions(monkeypatch):
    clear_region_cache()
    # Mock SCAN_REGIONS with a list of regions
    monkeypatch.setattr(settings, "SCAN_REGIONS", "us-east-1,  eu-west-1,ap-south-1 ")
    
    regions = get_all_regions()
    assert regions == ["us-east-1", "eu-west-1", "ap-south-1"]

def test_region_cache_is_cached(monkeypatch):
    clear_region_cache()
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
