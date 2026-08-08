import boto3
import logging
from app.services.aws.session import get_aws_session

logger = logging.getLogger("scanner")

_cached_regions: list | None = None

def get_all_regions() -> list:
    """Return the list of all enabled AWS regions. Cached after first call."""
    global _cached_regions
    if _cached_regions is not None:
        return _cached_regions
    try:
        session = get_aws_session()
        ec2_client = session.client('ec2', region_name=session.region_name or 'us-east-1')
        _cached_regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
        logger.info(f"Cached {len(_cached_regions)} AWS regions")
    except Exception as e:
        logger.error(f"Failed to list AWS regions: {e}")
        _cached_regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-south-1']
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
