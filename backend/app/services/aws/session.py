import boto3
import logging
from app.config import settings

logger = logging.getLogger("backend")

_cached_account_id: str | None = None

def get_aws_session() -> boto3.Session:
    try:
        # Check if profile is active
        session = boto3.Session(profile_name=settings.AWS_PROFILE)
        logger.debug(f"AWS session created using profile: {settings.AWS_PROFILE}")
        return session
    except Exception as e:
        logger.warning(f"Could not load profile '{settings.AWS_PROFILE}': {str(e)}. Attempting default session.")
        try:
            session = boto3.Session()
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
