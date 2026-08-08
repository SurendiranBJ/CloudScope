import logging
import concurrent.futures
from app.services.aws.session import get_account_id
from app.services.aws.region_cache import get_all_regions, make_region_sessions

logger = logging.getLogger("scanner")

def collect_rds_instances() -> list:
    instances = []
    try:
        account_id = get_account_id()
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def fetch_region_rds(region_name):
            region_db = []
            try:
                client = region_sessions[region_name].client('rds', region_name=region_name)
                paginator = client.get_paginator('describe_db_instances')
                for page in paginator.paginate():
                    for db in page.get('DBInstances', []):
                        db_id = db['DBInstanceIdentifier']
                        status = db.get('DBInstanceStatus', 'unknown')
                        engine = db.get('Engine', 'unknown')
                        publicly_accessible = db.get('PubliclyAccessible', False)
                        storage_encrypted = db.get('StorageEncrypted', False)
                        multi_az = db.get('MultiAZ', False)
                        arn = db.get('DBInstanceArn', f"arn:aws:rds:{region_name}:{account_id}:db:{db_id}")

                        region_db.append({
                            "id": db_id,
                            "name": db_id,
                            "type": "RDS",
                            "region": region_name,
                            "riskScore": 0,
                            "status": status,
                            "owner": account_id,
                            "arn": arn,
                            "details": {
                                "engine": engine,
                                "publicly_accessible": publicly_accessible,
                                "storage_encrypted": storage_encrypted,
                                "multi_az": multi_az
                            }
                        })
            except Exception as e:
                logger.debug(f"Failed to fetch RDS in {region_name}: {e}")
            return region_db

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(fetch_region_rds, regions):
                instances.extend(res)

        logger.info(f"RDS Collector: Discovered {len(instances)} databases across all regions")
    except Exception as e:
        logger.error(f"RDS Collector failed: {e}")
    return instances
