import boto3
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from app.config import settings
from botocore.credentials import RefreshableCredentials
from botocore.session import Session as BotocoreSession

from botocore.config import Config

logger = logging.getLogger("backend")

_cached_account_id: Optional[str] = None
_assumed_role_credentials: Dict[tuple, RefreshableCredentials] = {}
_assumed_role_lock = threading.Lock()

DEFAULT_BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=15,
    retries={'max_attempts': 2}
)

def get_boto_config(connect_timeout: int = 5, read_timeout: int = 15, max_attempts: int = 2) -> Config:
    return Config(
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        retries={'max_attempts': max_attempts}
    )


def get_aws_session(region_name: Optional[str] = None) -> boto3.Session:
    """Create a boto3 Session, optionally scoped to a specific region.

    Uses the configured AWS_PROFILE if available, falling back to environment
    credentials if the profile is not found or not configured.

    Args:
        region_name: If provided, the session is pinned to this AWS region.
                     Otherwise, the session uses the profile/environment default.
    """
    project_id = None
    try:
        from app.services.project_context import get_project_id
        project_id = get_project_id()
        if not project_id:
            from app.services.scanner.scan_manager import scan_manager
            project_id = getattr(scan_manager, "_active_project_id", None)
    except Exception:
        project_id = None

    if project_id:
        return _get_project_aws_session(project_id, region_name)

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


def _get_project_aws_session(project_id: str, region_name: Optional[str]) -> boto3.Session:
    """Assume a verified project's role with SDK-managed credential refresh."""
    from app.persistence.database import get_db_session
    from app.persistence.models import CloudProjectModel

    with get_db_session() as db:
        project = db.query(CloudProjectModel).filter_by(project_id=project_id, status="ACTIVE").first()
        if not project or not project.role_arn or project.verification_status != "CONNECTED":
            raise RuntimeError("Selected AWS project has no verified read role")
        role_arn = project.role_arn
        external_id = project.external_id
        expected_account = project.account_id or role_arn.split(":")[4]
        revision = project.updated_at or ""

    if not external_id:
        raise RuntimeError("Selected AWS project is missing its ExternalId")
    key = (project_id, role_arn, external_id, revision)
    with _assumed_role_lock:
        credentials = _assumed_role_credentials.get(key)
        if credentials is None:
            profile = settings.AWS_PROFILE if settings.AWS_PROFILE else None
            try:
                source = boto3.Session(profile_name=profile) if profile else boto3.Session()
            except Exception:
                source = boto3.Session()
            sts = source.client("sts", config=get_boto_config())

            def refresh_credentials() -> dict[str, str]:
                response = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=f"CloudScopeScan-{project_id[:8]}",
                    ExternalId=external_id,
                    DurationSeconds=3600,
                )
                role_credentials = response["Credentials"]
                identity = boto3.Session(
                    aws_access_key_id=role_credentials["AccessKeyId"],
                    aws_secret_access_key=role_credentials["SecretAccessKey"],
                    aws_session_token=role_credentials["SessionToken"],
                ).client("sts", config=get_boto_config()).get_caller_identity()
                if identity.get("Account") != expected_account:
                    raise RuntimeError("Assumed AWS role returned an unexpected account identity")
                expiry = role_credentials.get("Expiration")
                if expiry is None:
                    expiry = datetime.now(timezone.utc) + timedelta(minutes=55)
                elif expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                return {
                    "access_key": role_credentials["AccessKeyId"],
                    "secret_key": role_credentials["SecretAccessKey"],
                    "token": role_credentials["SessionToken"],
                    "expiry_time": expiry.astimezone(timezone.utc).isoformat(),
                }

            metadata = refresh_credentials()
            credentials = RefreshableCredentials.create_from_metadata(
                metadata=metadata,
                refresh_using=refresh_credentials,
                method="cloudscope-assume-role",
            )
            for cached_key in list(_assumed_role_credentials):
                if cached_key[0] == project_id and cached_key != key:
                    _assumed_role_credentials.pop(cached_key, None)
            _assumed_role_credentials[key] = credentials

    botocore_session = BotocoreSession()
    botocore_session._credentials = credentials
    botocore_session.set_config_variable("region", region_name or settings.AWS_DEFAULT_REGION)
    return boto3.Session(botocore_session=botocore_session, region_name=region_name)


def get_account_id() -> str:
    """Retrieve and cache the real AWS account ID via STS GetCallerIdentity."""
    global _cached_account_id
    if _cached_account_id is not None:
        return _cached_account_id
    try:
        session = get_aws_session()
        sts = session.client('sts', config=get_boto_config(connect_timeout=5, read_timeout=15, max_attempts=2))
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
        sts = session.client('sts', config=get_boto_config(connect_timeout=5, read_timeout=15, max_attempts=2))
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
        logger.error(f"AWS authentication check failed: {str(e)}")
        return {
            "authenticated": False,
            "account_id": None,
            "arn": None,
            "user_id": None,
            "profile": settings.AWS_PROFILE,
            "region": settings.AWS_DEFAULT_REGION,
            "error": "Unable to locate credentials or verify AWS session"
        }
