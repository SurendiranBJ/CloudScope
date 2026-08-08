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
            creation_date = b.get('CreationDate')
            region = "us-east-1"  # Default fallback

            # S3 client get_bucket_location requires querying per bucket
            try:
                loc = client.get_bucket_location(Bucket=name)
                region = loc.get('LocationConstraint') or "us-east-1"
            except Exception:
                pass

            # Public Access Block Check
            public_blocked = True
            try:
                pab = client.get_public_access_block(Bucket=name)
                conf = pab.get('PublicAccessBlockConfiguration', {})
                public_blocked = conf.get('BlockPublicPolicy', True) and conf.get('RestrictPublicBuckets', True)
            except Exception as e:
                # If no public access block is set, default to False (potentially public)
                if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                    public_blocked = False

            # Encryption Check
            encrypted = False
            try:
                enc = client.get_bucket_encryption(Bucket=name)
                if enc.get('ServerSideEncryptionConfiguration'):
                    encrypted = True
            except Exception:
                pass

            # Versioning Check
            versioning_enabled = False
            try:
                ver = client.get_bucket_versioning(Bucket=name)
                versioning_enabled = ver.get('Status') == 'Enabled'
            except Exception:
                pass

            # Try to get bucket tags for owner info
            owner = account_id
            try:
                tags_resp = client.get_bucket_tagging(Bucket=name)
                for tag in tags_resp.get('TagSet', []):
                    if tag['Key'] == 'Owner':
                        owner = tag['Value']
                        break
            except Exception:
                pass

            # Determine status based on security posture
            if not public_blocked:
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
                "riskScore": 0,  # Calculated downstream
                "status": status,
                "owner": owner,
                "arn": f"arn:aws:s3:::{name}",
                "details": {
                    "public_blocked": public_blocked,
                    "encrypted": encrypted,
                    "versioning": versioning_enabled
                }
            })
        logger.info(f"S3 Collector: Discovered {len(buckets)} buckets")
    except Exception as e:
        logger.error(f"S3 Collector failed to list buckets: {str(e)}")
    return buckets
