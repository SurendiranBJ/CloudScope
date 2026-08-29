import logging
import json
import concurrent.futures
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
                    # Keep name→ARN so scan_manager can resolve AWS-managed policy documents
                    policy_arns = {
                        p['PolicyName']: p['PolicyArn']
                        for p in attached_policies.get('AttachedPolicies', [])
                    }
                except Exception:
                    policy_names = []
                    policy_arns = {}

                # Get Inline Policies & Documents
                user_inline_docs = {}
                try:
                    inline_policies = client.list_user_policies(UserName=username)
                    inline_names = inline_policies.get('PolicyNames', [])
                    for in_name in inline_names:
                        inline_label = f"[inline] {in_name}"
                        policy_names.append(inline_label)
                        try:
                            in_doc_resp = client.get_user_policy(UserName=username, PolicyName=in_name)
                            user_inline_docs[inline_label] = json.dumps(in_doc_resp.get('PolicyDocument', {}))
                        except Exception:
                            pass
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
                    "attachedPolicyArns": policy_arns,  # name -> ARN, for AWS-managed doc resolution
                    "inlinePolicyDocuments": user_inline_docs,
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
                group_name = g['GroupName']

                # Get Attached Managed Policies
                attached_policy_names = []
                attached_policy_arns = {}
                try:
                    group_policies = client.list_attached_group_policies(GroupName=group_name)
                    attached_policy_names = [p['PolicyName'] for p in group_policies.get('AttachedPolicies', [])]
                    attached_policy_arns = {
                        p['PolicyName']: p['PolicyArn']
                        for p in group_policies.get('AttachedPolicies', [])
                    }
                except Exception:
                    pass

                # Get Inline Policies & Documents
                group_inline_docs = {}
                try:
                    inline_policies = client.list_group_policies(GroupName=group_name)
                    inline_names = inline_policies.get('PolicyNames', [])
                    for in_name in inline_names:
                        inline_label = f"[inline] {in_name}"
                        attached_policy_names.append(inline_label)
                        try:
                            in_doc_resp = client.get_group_policy(GroupName=group_name, PolicyName=in_name)
                            group_inline_docs[inline_label] = json.dumps(in_doc_resp.get('PolicyDocument', {}))
                        except Exception:
                            pass
                except Exception:
                    pass

                groups_data.append({
                    "id": g['GroupId'],
                    "name": group_name,
                    "arn": g['Arn'],
                    "attachedPolicies": attached_policy_names,
                    "attachedPolicyArns": attached_policy_arns,
                    "inlinePolicyDocuments": group_inline_docs
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
                attached_policy_arns = {}
                try:
                    role_policies = client.list_attached_role_policies(RoleName=role_name)
                    attached_policy_names = [p['PolicyName'] for p in role_policies.get('AttachedPolicies', [])]
                    # Keep name→ARN so scan_manager can resolve AWS-managed policy documents
                    attached_policy_arns = {
                        p['PolicyName']: p['PolicyArn']
                        for p in role_policies.get('AttachedPolicies', [])
                    }
                except Exception:
                    pass

                # Get Inline Policies & Documents
                role_inline_docs = {}
                try:
                    inline_policies = client.list_role_policies(RoleName=role_name)
                    inline_names = inline_policies.get('PolicyNames', [])
                    for in_name in inline_names:
                        inline_label = f"[inline] {in_name}"
                        attached_policy_names.append(inline_label)
                        try:
                            in_doc_resp = client.get_role_policy(RoleName=role_name, PolicyName=in_name)
                            role_inline_docs[inline_label] = json.dumps(in_doc_resp.get('PolicyDocument', {}))
                        except Exception:
                            pass
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
                    "attachedPolicyArns": attached_policy_arns,  # name -> ARN, for AWS-managed doc resolution
                    "inlinePolicyDocuments": role_inline_docs,
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


def fetch_managed_policy_documents(policy_arns: set) -> dict:
    """Fetch IAM policy documents for a specific set of AWS-managed policy ARNs.

    Only the ARNs explicitly passed are fetched — this never enumerates the
    full AWS-managed policy catalog. Intended to be called by scan_manager
    with the union of ARNs actually attached to the users/roles found in the
    current scan.

    Args:
        policy_arns: A set of policy ARN strings
            (e.g. {"arn:aws:iam::aws:policy/AdministratorAccess"}). ARNs that
            are not AWS-managed (i.e. do not contain "::aws:policy/") are
            silently skipped — they are already handled by collect_policies().

    Returns:
        A dict mapping policy name -> JSON document string for every ARN that
        was successfully resolved. ARNs that fail (e.g. rate-limited, no
        permission) are omitted; the risk_engine name-substring fallback will
        cover those cases.
    """
    result = {}
    if not policy_arns:
        return result

    try:
        get_aws_session()
    except Exception as e:
        logger.error(f"IAM fetch_managed_policy_documents: failed to get session: {e}")
        return result

    target_arns = [arn for arn in policy_arns if '::aws:policy/' in arn]
    if not target_arns:
        return result

    def fetch_single_policy(arn):
        try:
            session = get_aws_session()
            client = session.client('iam')
            pol = client.get_policy(PolicyArn=arn)
            default_ver = pol['Policy']['DefaultVersionId']
            pol_ver = client.get_policy_version(PolicyArn=arn, VersionId=default_ver)
            doc = pol_ver.get('PolicyVersion', {}).get('Document', {})
            policy_name = pol['Policy']['PolicyName']
            logger.debug(f"Resolved AWS-managed policy document: {policy_name} ({arn})")
            return policy_name, json.dumps(doc)
        except Exception as e:
            logger.warning(f"Could not fetch document for AWS-managed policy {arn}: {e}")
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_single_policy, arn): arn for arn in target_arns}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                policy_name, doc_str = res
                result[policy_name] = doc_str

    logger.info(
        f"IAM fetch_managed_policy_documents: resolved {len(result)}/{len(policy_arns)} "
        f"AWS-managed policy documents"
    )
    return result
