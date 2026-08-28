import boto3
import logging
from app.config import settings

logger = logging.getLogger("backend")

_cached_account_id: str | None = None

def get_aws_session(region_name: str | None = None) -> boto3.Session:
    """Create a boto3 Session, optionally scoped to a specific region.

    Args:
        region_name: If provided, the session is pinned to this AWS region.
                     Otherwise, the session uses the profile/environment default.
    """
    try:
        # Check if profile is active
        session = boto3.Session(
            profile_name=settings.AWS_PROFILE,
            region_name=region_name
        )
        logger.debug(f"AWS session created using profile: {settings.AWS_PROFILE}, region: {region_name or 'default'}")
        return session
    except Exception as e:
        logger.warning(f"Could not load profile '{settings.AWS_PROFILE}': {str(e)}. Attempting default session.")
        try:
            session = boto3.Session(region_name=region_name)
            return session
        except Exception as err:
            logger.error(f"Failed to create default AWS session: {str(err)}")
            raise err

def get_account_id() -> str:
    """Retrieve and cache the real AWS account ID via STS GetCallerIdentity."""
    global _cached_account_id
    if _cached_account_id is not None:
        return _cached_account_id
    try:
        session = get_aws_session()
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        _cached_account_id = identity['Account']
        logger.info(f"Resolved AWS Account ID: {_cached_account_id}")
        return _cached_account_id
    except Exception as e:
        logger.error(f"Failed to resolve AWS account ID: {str(e)}")
        return "unknown"
