import logging
from app.services.aws.session import get_aws_session, get_account_id

logger = logging.getLogger("scanner")


def collect_lambda_functions() -> list:
    functions = []
    try:
        session = get_aws_session()
        account_id = get_account_id()
        
        # Get all enabled regions
        ec2_client = session.client('ec2', region_name=session.region_name or 'us-east-1')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for region in regions:
            try:
                client = session.client('lambda', region_name=region)
                response = client.list_functions()

                for fn in response.get('Functions', []):
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

                    # Try to get function tags for owner info
                    owner = account_id
                    try:
                        tags_resp = client.list_tags(Resource=arn)
                        for key, value in tags_resp.get('Tags', {}).items():
                            if key == 'Owner':
                                owner = value
                                break
                    except Exception:
                        pass

                    functions.append({
                        "id": name,
                        "name": name,
                        "type": "Lambda",
                        "region": region,
                        "riskScore": 0,  # Calculated downstream
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
                logger.debug(f"Failed to fetch lambdas in region {region}: {str(e)}")
                
        logger.info(f"Lambda Collector: Discovered {len(functions)} functions across all regions")
    except Exception as e:
        logger.error(f"Lambda Collector failed to list functions: {str(e)}")
    return functions
