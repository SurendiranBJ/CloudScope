import boto3
import logging
from typing import Dict, Any, Optional
from app.config import settings

logger = logging.getLogger("backend")

_cached_account_id: Optional[str] = None


def get_aws_session(region_name: Optional[str] = None) -> boto3.Session:
    """Create a boto3 Session, optionally scoped to a specific region.

    Uses the configured AWS_PROFILE if available, falling back to environment
    credentials if the profile is not found or not configured.

    Args:
        region_name: If provided, the session is pinned to this AWS region.
                     Otherwise, the session uses the profile/environment default.
    """
    profile = settings.AWS_PROFILE if settings.AWS_PROFILE else None
    
    if profile:
        try:
            session = boto3.Session(
                profile_name=profile,
                region_name=region_name
            )
            logger.debug(f"AWS session created with profile '{profile}', region '{region_name or session.region_name}'")
            return session
        except Exception as e:
            logger.warning(f"Could not initialize session with profile '{profile}': {e}. Falling back to default credentials.")

    try:
        session = boto3.Session(region_name=region_name)
        logger.debug(f"AWS default session created, region '{region_name or session.region_name}'")
        return session
    except Exception as err:
        logger.error(f"Failed to initialize AWS session: {err}")
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
        logger.error(f"Failed to resolve AWS account ID: {e}")
        return "unknown"


def get_aws_diagnostic_info() -> Dict[str, Any]:
    """Execute STS GetCallerIdentity to verify AWS connection safely.

    NEVER exposes secret access keys or credentials.
    """
    try:
        session = get_aws_session()
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity.get('Account')
        arn = identity.get('Arn')
        user_id = identity.get('UserId')
        region = session.region_name or settings.AWS_DEFAULT_REGION or "unknown"
        
        logger.info(f"AWS authentication successful. Account: {account_id}, ARN: {arn}")
        return {
            "authenticated": True,
            "account_id": account_id,
            "arn": arn,
            "user_id": user_id,
            "profile": settings.AWS_PROFILE,
            "region": region,
            "error": None
        }
    except Exception as e:
        err_msg = str(e)
        logger.error(f"AWS authentication check failed: {err_msg}")
        return {
            "authenticated": False,
            "account_id": None,
            "arn": None,
            "user_id": None,
            "profile": settings.AWS_PROFILE,
            "region": settings.AWS_DEFAULT_REGION,
            "error": err_msg
        }
