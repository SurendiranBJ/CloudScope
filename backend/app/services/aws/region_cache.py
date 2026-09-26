import boto3
import logging
from app.config import settings
from app.services.aws.session import get_aws_session, get_boto_config

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

logger = logging.getLogger("scanner")

@dataclass
class RegionalCollectionResult:
    """Typed result model for regional AWS resource collection with sequence compatibility."""
    items: List[Dict[str, Any]] = field(default_factory=list)
    regional_status: Dict[str, str] = field(default_factory=dict)
    successful_regions: List[str] = field(default_factory=list)
    failed_regions: List[str] = field(default_factory=list)

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)

    def __getitem__(self, index):
        return self.items[index]

_cached_regions: List[str] | None = None
_cached_mode: str | None = None

# Runtime-settable scan mode state (not persisted across restarts).
# Use set_scan_mode() to update; clear_region_cache() is called automatically.
_scan_mode: str = "auto"          # "auto" | "single" | "global"
_selected_region: str | None = None


def set_scan_mode(mode: str, region: str | None = None) -> None:
    """Update the active scan mode at runtime. Clears the region cache so the
    change takes effect on the next call to get_all_regions().

    Args:
        mode: "single" to scan one region, "global" to sweep all enabled regions, or "auto".
        region: The specific region code to use when mode is "single". Ignored for "global".
    """
    global _scan_mode, _selected_region
    _scan_mode = mode
    _selected_region = region if mode == "single" else None
    clear_region_cache()
    logger.info(f"Scan mode updated: mode={_scan_mode}, region={_selected_region}")


def get_scan_mode_state() -> dict:
    """Return the current runtime scan mode state for health / status endpoints."""
    # Ensure regions are resolved
    regions = get_all_regions()
    return {
        "mode": _cached_mode or "global",
        "selected_region": _selected_region,
        "resolved_regions": list(regions),
    }


def get_resolved_scan_mode() -> str:
    """Return the resolved scan mode string: 'single', 'configured', or 'global'."""
    get_all_regions()
    return _cached_mode or "global"


def get_all_regions() -> List[str]:
    """Return the list of AWS regions to scan, based on the active scan mode and priority.

    Required resolution priority:
    1. Explicit runtime single-region selection (_scan_mode == 'single' and _selected_region is set)
       -> mode: 'single', returns [_selected_region]
    2. Explicit SCAN_REGIONS configuration (settings.SCAN_REGIONS non-empty)
       -> mode: 'configured', returns deterministic sorted list of configured regions
    3. Dynamic DescribeRegions discovery (ec2.describe_regions with enabled opt-in status)
       -> mode: 'global', returns deterministic sorted list of all enabled AWS regions
    4. AWS session/default-region fallback only as a final safety fallback
       -> mode: 'single' / fallback default

    Result is cached after the first call; call clear_region_cache() to invalidate.
    """
    global _cached_regions, _cached_mode
    if _cached_regions is not None and _cached_mode is not None:
        return _cached_regions

    # --- Priority 1: Explicit runtime single-region selection ---
    if _scan_mode == "single" and _selected_region:
        _cached_mode = "single"
        _cached_regions = [_selected_region]
        logger.info(f"Priority 1 (Runtime Single): scanning selected region {_selected_region}")
        return _cached_regions

    # --- Priority 2: Explicit SCAN_REGIONS configuration (unless runtime explicitly requested 'global') ---
    if _scan_mode != "global" and settings.SCAN_REGIONS:
        raw_configured = [r.strip() for r in settings.SCAN_REGIONS.split(",") if r.strip()]
        if raw_configured:
            # Deterministic, unique, sorted list
            _cached_mode = "configured"
            _cached_regions = sorted(list(dict.fromkeys(raw_configured)))
            logger.info(f"Priority 2 (Configured Override): scanning {len(_cached_regions)} configured regions: {_cached_regions}")
            return _cached_regions

    # --- Priority 3: Dynamic DescribeRegions discovery (default when SCAN_REGIONS is empty or mode is 'global') ---
    try:
        session = get_aws_session()
        # Query describe_regions using session region or default
        probe_region = session.region_name or settings.AWS_DEFAULT_REGION or "us-east-1"
        ec2 = session.client("ec2", region_name=probe_region, config=get_boto_config(connect_timeout=5, read_timeout=15, max_attempts=2))
        response = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        discovered = [r["RegionName"] for r in response.get("Regions", []) if r.get("RegionName")]
        if discovered:
            # Deterministic alphabetical ordering
            _cached_mode = "global"
            _cached_regions = sorted(list(set(discovered)))
            logger.info(f"Priority 3 (Dynamic Discovery): resolved {len(_cached_regions)} enabled AWS regions: {_cached_regions}")
            return _cached_regions
        else:
            logger.warning("DescribeRegions returned zero enabled regions. Proceeding to safety fallback.")
    except Exception as e:
        logger.error(f"Priority 3 (Dynamic Discovery) failed: {e}. Falling back to AWS session default region.")

    # --- Priority 4: AWS session/default-region fallback only as a final safety fallback ---
    fallback_region = _get_session_default_region()
    _cached_mode = "single"
    _cached_regions = [fallback_region]
    logger.info(f"Priority 4 (Safety Fallback): scanning fallback region {fallback_region}")
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
    global _cached_regions, _cached_mode
    _cached_regions = None
    _cached_mode = None
