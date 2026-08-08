import logging
import json
from datetime import datetime, timezone
from app.services.aws.session import get_aws_session, get_account_id

logger = logging.getLogger("scanner")


def _format_last_active(dt: datetime | None) -> str:
    """Convert a datetime to a human-readable 'time ago' string."""
    if dt is None:
        return "Never"
    now = datetime.now(timezone.utc)
    # Ensure dt is timezone-aware
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = now - dt
    seconds = int(diff.total_seconds())
    if seconds < 60:
        return f"{seconds} seconds ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = hours // 24
    if days < 30:
        return f"{days} day{'s' if days != 1 else ''} ago"
    months = days // 30
    return f"{months} month{'s' if months != 1 else ''} ago"


def _get_user_last_active(client, username: str) -> str:
    """Get last activity time from PasswordLastUsed or access key LastUsedDate."""
    try:
        user_detail = client.get_user(UserName=username)
        password_last_used = user_detail['User'].get('PasswordLastUsed')
        if password_last_used:
            return _format_last_active(password_last_used)
    except Exception:
        pass

    # Check access keys last used
    try:
        keys = client.list_access_keys(UserName=username)
        latest_used = None
        for key_meta in keys.get('AccessKeyMetadata', []):
            key_id = key_meta['AccessKeyId']
            try:
                last_used_resp = client.get_access_key_last_used(AccessKeyId=key_id)
                last_used_date = last_used_resp.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                if last_used_date and (latest_used is None or last_used_date > latest_used):
                    latest_used = last_used_date
            except Exception:
                pass
        if latest_used:
            return _format_last_active(latest_used)
    except Exception:
        pass

    return "Never"


def collect_users() -> list:
    users_data = []
    try:
        session = get_aws_session()
        client = session.client('iam')
        paginator = client.get_paginator('list_users')

        for page in paginator.paginate():
            for u in page['Users']:
                username = u['UserName']
                arn = u['Arn']
                user_id = u['UserId']

                # Check MFA
                try:
                    mfa_devices = client.list_mfa_devices(UserName=username)
                    mfa_enabled = len(mfa_devices.get('MFADevices', [])) > 0
                except Exception:
                    mfa_enabled = False

                # Get Groups
                try:
                    groups = client.list_groups_for_user(UserName=username)
                    group_names = [g['GroupName'] for g in groups.get('Groups', [])]
                except Exception:
                    group_names = []

                # Get Attached Policies
                try:
                    attached_policies = client.list_attached_user_policies(UserName=username)
                    policy_names = [p['PolicyName'] for p in attached_policies.get('AttachedPolicies', [])]
                except Exception:
                    policy_names = []

                # Get Inline Policies
                try:
                    inline_policies = client.list_user_policies(UserName=username)
                    inline_names = inline_policies.get('PolicyNames', [])
                    policy_names.extend([f"[inline] {name}" for name in inline_names])
                except Exception:
                    pass

                # Compute last active
                last_active = _get_user_last_active(client, username)

                # Determine status from password/key activity
                password_last_used = u.get('PasswordLastUsed')
                create_date = u.get('CreateDate')
                status = "active" if password_last_used or last_active != "Never" else "inactive"

                users_data.append({
                    "id": user_id,
                    "name": username,
                    "arn": arn,
                    "status": status,
                    "policies": policy_names,
                    "groups": group_names,
                    "riskScore": 0,  # Calculated downstream by risk_engine
                    "mfaEnabled": mfa_enabled,
                    "lastActive": last_active,
                    "type": "User",
                    "region": "global",
                    "owner": get_account_id()
                })
        logger.info(f"IAM Collector: Discovered {len(users_data)} users")
    except Exception as e:
        logger.error(f"IAM Collector failed to list users: {str(e)}")
    return users_data


def collect_groups() -> list:
    groups_data = []
    try:
        session = get_aws_session()
        client = session.client('iam')
        paginator = client.get_paginator('list_groups')

        for page in paginator.paginate():
            for g in page['Groups']:
                groups_data.append({
                    "id": g['GroupId'],
                    "name": g['GroupName'],
                    "arn": g['Arn']
                })
        logger.info(f"IAM Collector: Discovered {len(groups_data)} groups")
    except Exception as e:
        logger.error(f"IAM Collector failed to list groups: {str(e)}")
    return groups_data


def collect_roles() -> list:
    roles_data = []
    try:
        session = get_aws_session()
        client = session.client('iam')
        paginator = client.get_paginator('list_roles')

        for page in paginator.paginate():
            for r in page['Roles']:
                role_name = r['RoleName']
                arn = r['Arn']
                desc = r.get('Description', 'No description registered')

                # Trust Policy Document
                trust_doc = r.get('AssumeRolePolicyDocument', {})
                trust_policy_str = json.dumps(trust_doc)

                # Get attached policies for the role
                attached_policy_names = []
                try:
                    role_policies = client.list_attached_role_policies(RoleName=role_name)
                    attached_policy_names = [p['PolicyName'] for p in role_policies.get('AttachedPolicies', [])]
                except Exception:
                    pass

                roles_data.append({
                    "name": role_name,
                    "arn": arn,
                    "trustPolicy": trust_policy_str,
                    "description": desc,
                    "activeSessions": 0,
                    "riskScore": 0,  # Calculated downstream
                    "attachedPolicies": attached_policy_names,
                    "type": "Role",
                    "region": "global",
                    "status": "active",
                    "owner": get_account_id()
                })
        logger.info(f"IAM Collector: Discovered {len(roles_data)} roles")
    except Exception as e:
        logger.error(f"IAM Collector failed to list roles: {str(e)}")
    return roles_data


def collect_policies() -> list:
    policies_data = []
    try:
        session = get_aws_session()
        client = session.client('iam')
        paginator = client.get_paginator('list_policies')

        for page in paginator.paginate(Scope='Local'):
            for p in page['Policies']:
                pol_name = p['PolicyName']
                arn = p['Arn']

                # Fetch default policy document version
                try:
                    default_ver = p['DefaultVersionId']
                    pol_ver = client.get_policy_version(PolicyArn=arn, VersionId=default_ver)
                    doc = pol_ver.get('PolicyVersion', {}).get('Document', {})
                    document_str = json.dumps(doc)
                except Exception:
                    document_str = "{}"

                policies_data.append({
                    "name": pol_name,
                    "arn": arn,
                    "type": "custom",
                    "document": document_str,
                    "riskScore": 0  # Calculated downstream
                })
        logger.info(f"IAM Collector: Discovered {len(policies_data)} custom policies")
    except Exception as e:
        logger.error(f"IAM Collector failed to list policies: {str(e)}")
    return policies_data
