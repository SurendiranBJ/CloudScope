import logging
import concurrent.futures
import time
from datetime import datetime
from app.services.aws.session import get_account_id
from app.services.aws.region_cache import get_all_regions, make_region_sessions

logger = logging.getLogger("scanner")


def collect_secrets() -> list:
    """Discover Secrets Manager metadata across all configured regions.

    SECURITY MANDATE: Collects metadata only (name, ARN, rotation status,
    tags, dates). NEVER retrieves or exposes secret values.
    """
    secrets = []
    try:
        account_id = get_account_id()
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def fetch_region_secrets(region_name):
            start = time.time()
            region_secrets = []
            try:
                client = region_sessions[region_name].client('secretsmanager', region_name=region_name)
                paginator = client.get_paginator('list_secrets')
                for page in paginator.paginate():
                    for sec in page.get('SecretList', []):
                        name = sec['Name']
                        arn = sec['ARN']
                        rotation = sec.get('RotationEnabled', False)
                        last_changed = sec.get('LastChangedDate', datetime.utcnow())
                        last_accessed = sec.get('LastAccessedDate')
                        description = sec.get('Description', '')

                        owner = account_id
                        tags = sec.get('Tags', [])
                        for tag in tags:
                            if tag.get('Key') == 'Owner':
                                owner = tag.get('Value', account_id)
                                break

                        region_secrets.append({
                            "id": name,
                            "name": name,
                            "type": "Secrets",
                            "region": region_name,
                            "riskScore": 0,  # Calculated downstream
                            "status": "configured" if rotation else "warning",
                            "owner": owner,
                            "arn": arn,
                            "details": {
                                "rotation_enabled": rotation,
                                "last_changed": last_changed.isoformat() if hasattr(last_changed, 'isoformat') else str(last_changed),
                                "last_accessed": last_accessed.isoformat() if last_accessed and hasattr(last_accessed, 'isoformat') else "Never",
                                "description": description
                            }
                        })
            except Exception as e:
                logger.debug(f"Failed to fetch Secrets in {region_name}: {e}")
            elapsed = time.time() - start
            logger.info(f"Secrets collection for region {region_name} completed in {elapsed:.2f}s")
            return region_secrets

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(fetch_region_secrets, regions):
                secrets.extend(res)

        logger.info(f"Secrets Collector: Discovered {len(secrets)} secrets across all regions")
    except Exception as e:
        logger.error(f"Secrets Collector failed: {e}")
    return secrets
