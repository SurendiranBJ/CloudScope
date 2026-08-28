import logging
import concurrent.futures
import time
from app.services.aws.session import get_aws_session, get_account_id
from app.services.aws.region_cache import get_all_regions, make_region_sessions

logger = logging.getLogger("scanner")

def collect_lambda_functions() -> list:
    functions = []
    try:
        account_id = get_account_id()
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def fetch_region_lambdas(region_name):
            start = time.time()
            region_funcs = []
            try:
                client = region_sessions[region_name].client('lambda', region_name=region_name)
                paginator = client.get_paginator('list_functions')
                for page in paginator.paginate():
                    for fn in page.get('Functions', []):
                        name = fn['FunctionName']
                        arn = fn['FunctionArn']
                        runtime = fn.get('Runtime', 'Unknown')
                        role_arn = fn['Role']
                        role_name = role_arn.split('/')[-1]
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
                                "memory_mb": memory,
                                "timeout_seconds": timeout,
                                "handler": handler,
                                "code_size_bytes": code_size,
                                "last_modified": last_modified
                            }
                        })
            except Exception as e:
                logger.debug(f"Failed to fetch lambdas in {region_name}: {e}")
            elapsed = time.time() - start
            logger.info(f"Lambda collection for region {region_name} completed in {elapsed:.2f}s")
            return region_funcs

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(fetch_region_lambdas, regions):
                functions.extend(res)

        logger.info(f"Lambda Collector: Discovered {len(functions)} functions across all regions")
    except Exception as e:
        logger.error(f"Lambda Collector failed: {e}")
    return functions
