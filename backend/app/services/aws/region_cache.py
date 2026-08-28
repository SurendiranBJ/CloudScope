import boto3
import logging
from app.config import settings
from app.services.aws.session import get_aws_session

logger = logging.getLogger("scanner")

_cached_regions: list | None = None

# Runtime-settable scan mode state (not persisted across restarts).
# Use set_scan_mode() to update; clear_region_cache() is called automatically.
_scan_mode: str = "single"          # "single" | "global"
_selected_region: str | None = None


def set_scan_mode(mode: str, region: str | None = None) -> None:
    """Update the active scan mode at runtime. Clears the region cache so the
    change takes effect on the next call to get_all_regions().

    Args:
        mode: "single" to scan one region, "global" to sweep all enabled regions.
        region: The specific region code to use when mode is "single". Ignored for "global".

    Note: This setting is NOT persisted across server restarts. To make a permanent
    change update SCAN_REGIONS in .env instead.
    """
    global _scan_mode, _selected_region
    _scan_mode = mode
    _selected_region = region if mode == "single" else None
    clear_region_cache()
    logger.info(f"Scan mode updated: mode={_scan_mode}, region={_selected_region}")


def get_scan_mode_state() -> dict:
    """Return the current runtime scan mode state for health / status endpoints."""
    return {
        "mode": _scan_mode,
        "selected_region": _selected_region,
    }


def get_all_regions() -> list:
    """Return the list of AWS regions to scan, based on the active scan mode.

    Resolution order:
    1. _scan_mode == "global"  → call describe_regions() and return all enabled regions.
    2. _scan_mode == "single" and _selected_region is set  → return [_selected_region].
    3. Otherwise (default)  → respect SCAN_REGIONS env var, then fall back to the
       AWS session's own default region (matches documented single-region scope).

    Result is cached after the first call; call clear_region_cache() to invalidate.
    """
    global _cached_regions
    if _cached_regions is not None:
        return _cached_regions

    # --- Mode: global — sweep all enabled regions via describe_regions() ---
    if _scan_mode == "global":
        try:
            session = get_aws_session()
            ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
            response = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
            _cached_regions = [r["RegionName"] for r in response.get("Regions", [])]
            logger.info(f"Global mode: discovered {len(_cached_regions)} enabled regions")
        except Exception as e:
            logger.error(f"Global region discovery failed: {e}. Falling back to session default.")
            _cached_regions = [_get_session_default_region()]
        return _cached_regions

    # --- Mode: single (runtime-selected region) ---
    if _scan_mode == "single" and _selected_region:
        _cached_regions = [_selected_region]
        logger.info(f"Single mode: scanning selected region {_selected_region}")
        return _cached_regions

    # --- Default fallback: env var → session default ---
    if settings.SCAN_REGIONS:
        regions = [r.strip() for r in settings.SCAN_REGIONS.split(",") if r.strip()]
        if regions:
            _cached_regions = regions
            logger.info(f"Using configured scan regions: {_cached_regions}")
            return _cached_regions

    _cached_regions = [_get_session_default_region()]
    return _cached_regions


def _get_session_default_region() -> str:
    """Resolve the default region from the boto3 session, with a hardcoded fallback."""
    try:
        session = get_aws_session()
        region = session.region_name or settings.AWS_DEFAULT_REGION or "us-east-1"
        logger.info(f"Using default region from AWS session: {region}")
        return region
    except Exception as e:
        logger.error(f"Failed to get default region from session: {e}")
        return settings.AWS_DEFAULT_REGION or "us-east-1"


def make_region_sessions(regions: list) -> dict:
    """Pre-create one boto3.Session per region (thread-safe once created)."""
    session = get_aws_session()
    profile = session.profile_name
    return {r: boto3.Session(region_name=r, profile_name=profile) for r in regions}


def clear_region_cache():
    """Force re-fetch on next call to get_all_regions()."""
    global _cached_regions
    _cached_regions = None


def get_selected_region() -> str:
    """Return the single target region for services that don't iterate regions.

    Resolution: _selected_region if set, otherwise the first entry from get_all_regions().
    Used by CloudTrail, AccessAnalyzer, and similar region-scoped but non-iterable services.
    """
    if _selected_region:
        return _selected_region
    regions = get_all_regions()
    return regions[0] if regions else "us-east-1"
