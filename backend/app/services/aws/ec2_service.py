import logging
import concurrent.futures
from app.services.aws.session import get_aws_session, get_account_id
from app.services.aws.region_cache import get_all_regions, make_region_sessions

logger = logging.getLogger("scanner")

def collect_ec2_instances() -> list:
    instances = []
    try:
        account_id = get_account_id()
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def fetch_region_ec2(region_name):
            region_instances = []
            try:
                client = region_sessions[region_name].client('ec2', region_name=region_name)
                paginator = client.get_paginator('describe_instances')
                for page in paginator.paginate():
                    for reservation in page.get('Reservations', []):
                        for inst in reservation.get('Instances', []):
                            inst_id = inst['InstanceId']
                            state = inst['State']['Name']
                            public_ip = inst.get('PublicIpAddress', 'None')
                            private_ip = inst.get('PrivateIpAddress', 'None')
                            inst_type = inst.get('InstanceType', 'unknown')

                            iam_profile_arn = inst.get('IamInstanceProfile', {}).get('Arn', 'None')
                            iam_role_name = 'None'
                            if iam_profile_arn != 'None':
                                iam_role_name = iam_profile_arn.split('/')[-1]

                            name = inst_id
                            owner = account_id
                            tags = inst.get('Tags', [])
                            for t in tags:
                                if t['Key'] == 'Name':
                                    name = t['Value']
                                elif t['Key'] == 'Owner':
                                    owner = t['Value']

                            sg_names = [sg['GroupName'] for sg in inst.get('SecurityGroups', [])]

                            region_instances.append({
                                "id": inst_id,
                                "name": name,
                                "type": "EC2",
                                "region": region_name,
                                "riskScore": 0,
                                "status": "active" if state == "running" else "stopped",
                                "owner": owner,
                                "arn": f"arn:aws:ec2:{region_name}:{account_id}:instance/{inst_id}",
                                "details": {
                                    "public_ip": public_ip,
                                    "private_ip": private_ip,
                                    "iam_role_name": iam_role_name,
                                    "instance_type": inst_type,
                                    "security_groups": sg_names
                                }
                            })
            except Exception as e:
                logger.debug(f"Failed to fetch EC2 in {region_name}: {e}")
            return region_instances

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for res in executor.map(fetch_region_ec2, regions):
                instances.extend(res)

        logger.info(f"EC2 Collector: Discovered {len(instances)} instances across all regions")
    except Exception as e:
        logger.error(f"EC2 Collector failed: {e}")
    return instances
