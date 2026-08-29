"""
CloudScope S3 Security Collector.

Collects S3 buckets and performs comprehensive security posture inspection:
- BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets
- Bucket Policy inspection for public principal (* / Anonymous)
- Server-side encryption status
- Object versioning status
"""

import json
import logging
from app.services.aws.session import get_aws_session, get_account_id

logger = logging.getLogger("scanner")


def collect_s3_buckets() -> list:
    buckets = []
    try:
        session = get_aws_session()
        client = session.client('s3')
        account_id = get_account_id()
        response = client.list_buckets()

        for b in response.get('Buckets', []):
            name = b['Name']
            region = "us-east-1"

            try:
                loc = client.get_bucket_location(Bucket=name)
                constraint = loc.get('LocationConstraint')
                if constraint:
                    # In AWS S3, EU location constraint maps to eu-west-1
                    region = "eu-west-1" if constraint == "EU" else constraint
                else:
                    region = "us-east-1"
            except Exception as loc_err:
                logger.debug(f"Could not get region for S3 bucket {name}: {loc_err}")

            # 1. Public Access Block Evaluation
            block_public_acls = False
            ignore_public_acls = False
            block_public_policy = False
            restrict_public_buckets = False
            pab_status = "UNKNOWN"

            try:
                pab = client.get_public_access_block(Bucket=name)
                conf = pab.get('PublicAccessBlockConfiguration', {})
                block_public_acls = conf.get('BlockPublicAcls', False)
                ignore_public_acls = conf.get('IgnorePublicAcls', False)
                block_public_policy = conf.get('BlockPublicPolicy', False)
                restrict_public_buckets = conf.get('RestrictPublicBuckets', False)
                pab_status = "CONFIGURED"
            except Exception as pab_err:
                err_str = str(pab_err)
                if 'NoSuchPublicAccessBlockConfiguration' in err_str:
                    pab_status = "NOT_CONFIGURED"
                elif 'AccessDenied' in err_str:
                    pab_status = "ACCESS_DENIED"
                else:
                    pab_status = "ERROR"

            # 2. Bucket Policy Evaluation for Public Access
            has_public_policy = False
            policy_status = "NO_POLICY"
            try:
                pol_resp = client.get_bucket_policy(Bucket=name)
                pol_str = pol_resp.get('Policy', '')
                if pol_str:
                    pol_doc = json.loads(pol_str)
                    statements = pol_doc.get('Statement', [])
                    if isinstance(statements, dict):
                        statements = [statements]
                    for stmt in statements:
                        if stmt.get('Effect') == 'Allow':
                            p = stmt.get('Principal', {})
                            if p == '*' or (isinstance(p, dict) and p.get('AWS') == '*'):
                                has_public_policy = True
                                policy_status = "PUBLIC_ALLOW"
                                break
                    if not has_public_policy:
                        policy_status = "RESTRICTED"
            except Exception as pol_err:
                err_str = str(pol_err)
                if 'NoSuchBucketPolicy' in err_str:
                    policy_status = "NO_POLICY"
                elif 'AccessDenied' in err_str:
                    policy_status = "ACCESS_DENIED"
                else:
                    policy_status = "ERROR"

            # Classify Exposure: PUBLIC, POTENTIALLY_PUBLIC, PRIVATE, UNKNOWN
            all_blocks_enabled = (
                block_public_acls and ignore_public_acls and
                block_public_policy and restrict_public_buckets
            )
            
            if has_public_policy and not block_public_policy:
                exposure_class = "PUBLIC"
                public_blocked = False
            elif pab_status == "NOT_CONFIGURED" or not all_blocks_enabled:
                exposure_class = "POTENTIALLY_PUBLIC"
                public_blocked = False
            elif all_blocks_enabled:
                exposure_class = "PRIVATE"
                public_blocked = True
            else:
                exposure_class = "UNKNOWN"
                public_blocked = False

            # 3. Server-Side Encryption Check
            encryption_status = "UNKNOWN"
            encrypted = False
            try:
                enc = client.get_bucket_encryption(Bucket=name)
                if enc.get('ServerSideEncryptionConfiguration'):
                    encrypted = True
                    encryption_status = "ENCRYPTED"
            except Exception as enc_err:
                err_str = str(enc_err)
                if 'ServerSideEncryptionConfigurationNotFoundError' in err_str:
                    encryption_status = "NOT_ENCRYPTED"
                elif 'AccessDenied' in err_str:
                    encryption_status = "ACCESS_DENIED"
                else:
                    encryption_status = "ERROR"

            # 4. Object Versioning Check
            versioning_status = "UNKNOWN"
            versioning_enabled = False
            try:
                ver = client.get_bucket_versioning(Bucket=name)
                v_stat = ver.get('Status')
                if v_stat == 'Enabled':
                    versioning_enabled = True
                    versioning_status = "ENABLED"
                elif v_stat == 'Suspended':
                    versioning_status = "SUSPENDED"
                else:
                    versioning_status = "DISABLED"
            except Exception as ver_err:
                err_str = str(ver_err)
                if 'AccessDenied' in err_str:
                    versioning_status = "ACCESS_DENIED"
                else:
                    versioning_status = "ERROR"

            # 5. Bucket Tagging for Owner Info
            owner = account_id
            try:
                tags_resp = client.get_bucket_tagging(Bucket=name)
                for tag in tags_resp.get('TagSet', []):
                    if tag['Key'] == 'Owner':
                        owner = tag['Value']
                        break
            except Exception:
                pass

            if exposure_class in ["PUBLIC", "POTENTIALLY_PUBLIC"]:
                status = "critical"
            elif not encrypted:
                status = "warning"
            else:
                status = "configured"

            buckets.append({
                "id": name,
                "name": name,
                "type": "S3",
                "region": region,
                "riskScore": 0,
                "status": status,
                "owner": owner,
                "arn": f"arn:aws:s3:::{name}",
                "details": {
                    "public_blocked": public_blocked,
                    "exposure_class": exposure_class,
                    "block_public_acls": block_public_acls,
                    "ignore_public_acls": ignore_public_acls,
                    "block_public_policy": block_public_policy,
                    "restrict_public_buckets": restrict_public_buckets,
                    "pab_status": pab_status,
                    "policy_status": policy_status,
                    "encrypted": encrypted,
                    "encryption_status": encryption_status,
                    "versioning": versioning_enabled,
                    "versioning_status": versioning_status
                }
            })
        logger.info(f"S3 Collector: Discovered {len(buckets)} buckets")
    except Exception as e:
        logger.error(f"S3 Collector failed to list buckets: {str(e)}")
    return buckets
