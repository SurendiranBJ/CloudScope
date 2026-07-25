import boto3
import logging
from app.config import settings

logger = logging.getLogger("backend")

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
