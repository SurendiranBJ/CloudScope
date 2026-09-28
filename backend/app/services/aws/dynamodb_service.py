import logging
import concurrent.futures
import time
from typing import Dict, List, Any
from app.services.aws.session import get_account_id, get_boto_config
from app.services.aws.region_cache import get_all_regions, make_region_sessions, RegionalCollectionResult

logger = logging.getLogger("scanner")

def collect_dynamodb_tables() -> RegionalCollectionResult:
    tables: List[Dict[str, Any]] = []
    regional_status: Dict[str, str] = {}
    successful_regions: List[str] = []
    failed_regions: List[str] = []

    try:
        account_id = get_account_id()
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def fetch_region_ddb(region_name: str):
            start = time.time()
            region_tables = []
            try:
                client = region_sessions[region_name].client('dynamodb', region_name=region_name, config=get_boto_config())
                paginator = client.get_paginator('list_tables')
                for page in paginator.paginate():
                    for table_name in page.get('TableNames', []):
                        try:
                            desc = client.describe_table(TableName=table_name)
                            table_details = desc.get('Table', {})

                            status = table_details.get('TableStatus', 'unknown')
                            item_count = table_details.get('ItemCount', 0)
                            size_bytes = table_details.get('TableSizeBytes', 0)
                            arn = table_details.get('TableArn', f"arn:aws:dynamodb:{region_name}:{account_id}:table/{table_name}")

                            pitr_enabled = False
                            try:
                                backup_desc = client.describe_continuous_backups(TableName=table_name)
                                pitr_status = backup_desc.get('ContinuousBackupsDescription', {}).get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus')
                                pitr_enabled = pitr_status == 'ENABLED'
                            except Exception:
                                pass

                            region_tables.append({
                                "id": table_name,
                                "name": table_name,
                                "type": "DynamoDB",
                                "region": region_name,
                                "riskScore": 0,
                                "status": status,
                                "owner": account_id,
                                "arn": arn,
                                "details": {
                                    "item_count": item_count,
                                    "size_bytes": size_bytes,
                                    "pitr_enabled": pitr_enabled
                                }
                            })
                        except Exception as e:
                            logger.debug(f"Failed to describe table {table_name} in {region_name}: {e}")
                elapsed = time.time() - start
                logger.info(f"DynamoDB collection for region {region_name} completed in {elapsed:.2f}s")
                return (region_name, "success" if region_tables else "empty", region_tables)
            except Exception as e:
                logger.debug(f"Failed to fetch DynamoDB in {region_name}: {e}")
                return (region_name, "failed", [])

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for rname, status, res in executor.map(fetch_region_ddb, regions):
                regional_status[rname] = status
                if status in ["success", "empty"]:
                    successful_regions.append(rname)
                    tables.extend(res)
                else:
                    failed_regions.append(rname)

        logger.info(f"DynamoDB Collector: Discovered {len(tables)} tables across {len(successful_regions)} region(s) ({len(failed_regions)} failed)")
        return RegionalCollectionResult(
            items=tables,
            regional_status=regional_status,
            successful_regions=successful_regions,
            failed_regions=failed_regions
        )
    except Exception as e:
        logger.error(f"DynamoDB Collector failed: {e}")
        raise e
