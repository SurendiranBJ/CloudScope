import logging
import concurrent.futures
from app.services.aws.session import get_account_id
from app.services.aws.region_cache import get_all_regions, make_region_sessions

logger = logging.getLogger("scanner")

def collect_dynamodb_tables() -> list:
    tables = []
    try:
        account_id = get_account_id()
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def fetch_region_ddb(region_name):
            region_tables = []
            try:
                client = region_sessions[region_name].client('dynamodb', region_name=region_name)
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
            except Exception as e:
                logger.debug(f"Failed to fetch DynamoDB in {region_name}: {e}")
            return region_tables

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(fetch_region_ddb, regions):
                tables.extend(res)

        logger.info(f"DynamoDB Collector: Discovered {len(tables)} tables across all regions")
    except Exception as e:
        logger.error(f"DynamoDB Collector failed: {e}")
    return tables
