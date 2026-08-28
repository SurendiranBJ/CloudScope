import boto3
import logging
from app.config import settings
from app.services.aws.session import get_aws_session

logger = logging.getLogger("scanner")

_cached_regions: list | None = None

def get_all_regions() -> list:
    """Return the list of configured scan regions, or default to the session's default region. Cached after first call."""
    global _cached_regions
    if _cached_regions is not None:
        return _cached_regions

    if settings.SCAN_REGIONS:
        regions = [r.strip() for r in settings.SCAN_REGIONS.split(",") if r.strip()]
        if regions:
            _cached_regions = regions
            logger.info(f"Using configured scan regions: {_cached_regions}")
            return _cached_regions

    try:
        session = get_aws_session()
        region = session.region_name or settings.AWS_DEFAULT_REGION or 'us-east-1'
        _cached_regions = [region]
        logger.info(f"Using default region from AWS session: {_cached_regions}")
    except Exception as e:
        logger.error(f"Failed to get default region from session: {e}")
        _cached_regions = [settings.AWS_DEFAULT_REGION or 'us-east-1']
    return _cached_regions


def make_region_sessions(regions: list) -> dict:
    """Pre-create one boto3.Session per region (thread-safe once created)."""
    session = get_aws_session()
    profile = session.profile_name
    return {r: boto3.Session(region_name=r, profile_name=profile) for r in regions}


def clear_region_cache():
    """Force re-fetch on next call."""
    global _cached_regions
    _cached_regions = None
