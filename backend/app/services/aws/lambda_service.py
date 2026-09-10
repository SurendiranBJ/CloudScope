import logging
import concurrent.futures
import time
from typing import Dict, List, Any
from app.services.aws.session import get_aws_session, get_account_id, get_boto_config
from app.services.aws.region_cache import get_all_regions, make_region_sessions, RegionalCollectionResult

logger = logging.getLogger("scanner")

def collect_lambda_functions() -> RegionalCollectionResult:
    functions: List[Dict[str, Any]] = []
    regional_status: Dict[str, str] = {}
    successful_regions: List[str] = []
    failed_regions: List[str] = []

    try:
        account_id = get_account_id()
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def fetch_region_lambdas(region_name: str):
            start = time.time()
            region_funcs = []
            try:
                client = region_sessions[region_name].client('lambda', region_name=region_name, config=get_boto_config())
                paginator = client.get_paginator('list_functions')
                for page in paginator.paginate():
                    for fn in page.get('Functions', []):
                        name = fn['FunctionName']
                        arn = fn['FunctionArn']
                        runtime = fn.get('Runtime', 'Unknown')
                        role_arn = fn.get('Role', '')
                        role_name = role_arn.split('/')[-1] if role_arn else 'None'
                        memory = fn.get('MemorySize', 128)
                        timeout = fn.get('Timeout', 3)
                        handler = fn.get('Handler', 'Unknown')
                        code_size = fn.get('CodeSize', 0)
                        last_modified = fn.get('LastModified', '')

                        owner = account_id
                        try:
                            tags_resp = client.list_tags(Resource=arn)
                            for key, value in tags_resp.get('Tags', {}).items():
                                if key == 'Owner':
                                    owner = value
                                    break
                        except Exception:
                            pass

                        region_funcs.append({
                            "id": name,
                            "name": name,
                            "type": "Lambda",
                            "region": region_name,
                            "riskScore": 0,
                            "status": "configured",
                            "owner": owner,
                            "arn": arn,
                            "details": {
                                "runtime": runtime,
                                "execution_role": role_name,
                                "role_arn": role_arn,
                                "memory_mb": memory,
                                "timeout_seconds": timeout,
                                "handler": handler,
                                "code_size_bytes": code_size,
                                "last_modified": last_modified
                            }
                        })

                elapsed = time.time() - start
                st = "SUCCESS_WITH_DATA" if len(region_funcs) > 0 else "SUCCESS_EMPTY"
                logger.info(f"Lambda collection for region {region_name} completed in {elapsed:.2f}s ({st}, {len(region_funcs)} functions)")
                return region_name, st, region_funcs
            except Exception as e:
                elapsed = time.time() - start
                err_st = f"FAILED: {e}"
                logger.warning(f"Lambda collection for region {region_name} failed in {elapsed:.2f}s: {e}")
                return region_name, err_st, []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for r_name, r_status, r_items in executor.map(fetch_region_lambdas, regions):
                regional_status[r_name] = r_status
                if r_status.startswith("FAILED"):
                    failed_regions.append(r_name)
                else:
                    successful_regions.append(r_name)
                    functions.extend(r_items)

        logger.info(
            f"Lambda Collector: Discovered {len(functions)} functions across {len(successful_regions)} successful regions "
            f"({len(failed_regions)} failed regions)"
        )
        return RegionalCollectionResult(
            items=functions,
            regional_status=regional_status,
            successful_regions=successful_regions,
            failed_regions=failed_regions
        )
    except Exception as e:
        logger.error(f"Lambda Collector top-level failed: {e}")
        raise e

