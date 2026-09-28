import logging
import concurrent.futures
import time
from typing import Dict, List, Any
from app.services.aws.session import get_account_id, get_boto_config
from app.services.aws.region_cache import get_all_regions, make_region_sessions, RegionalCollectionResult

logger = logging.getLogger("scanner")

def collect_rds_instances() -> RegionalCollectionResult:
    instances: List[Dict[str, Any]] = []
    regional_status: Dict[str, str] = {}
    successful_regions: List[str] = []
    failed_regions: List[str] = []

    try:
        account_id = get_account_id()
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def fetch_region_rds(region_name: str):
            start = time.time()
            region_db = []
            try:
                client = region_sessions[region_name].client('rds', region_name=region_name, config=get_boto_config())
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
                elapsed = time.time() - start
                logger.info(f"RDS collection for region {region_name} completed in {elapsed:.2f}s")
                return (region_name, "success" if region_db else "empty", region_db)
            except Exception as e:
                logger.debug(f"Failed to fetch RDS in {region_name}: {e}")
                return (region_name, "failed", [])

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for rname, status, res in executor.map(fetch_region_rds, regions):
                regional_status[rname] = status
                if status in ["success", "empty"]:
                    successful_regions.append(rname)
                    instances.extend(res)
                else:
                    failed_regions.append(rname)

        logger.info(f"RDS Collector: Discovered {len(instances)} databases across {len(successful_regions)} region(s) ({len(failed_regions)} failed)")
        return RegionalCollectionResult(
            items=instances,
            regional_status=regional_status,
            successful_regions=successful_regions,
            failed_regions=failed_regions
        )
    except Exception as e:
        logger.error(f"RDS Collector failed: {e}")
        raise e
