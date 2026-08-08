import logging
from app.services.aws.session import get_aws_session, get_account_id

logger = logging.getLogger("scanner")


def collect_ec2_instances() -> list:
    instances = []
    try:
        session = get_aws_session()
        account_id = get_account_id()
        
        # Get all enabled regions
        ec2_client = session.client('ec2', region_name=session.region_name or 'us-east-1')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        for region in regions:
            try:
                client = session.client('ec2', region_name=region)
                response = client.describe_instances()

                for reservation in response.get('Reservations', []):
                    for inst in reservation.get('Instances', []):
                        inst_id = inst['InstanceId']
                        state = inst['State']['Name']
                        public_ip = inst.get('PublicIpAddress', 'None')
                        private_ip = inst.get('PrivateIpAddress', 'None')
                        inst_type = inst.get('InstanceType', 'unknown')

                        # Attached IAM Instance Profile Role name
                        iam_profile_arn = inst.get('IamInstanceProfile', {}).get('Arn', 'None')
                        iam_role_name = 'None'
                        if iam_profile_arn != 'None':
                            iam_role_name = iam_profile_arn.split('/')[-1]

                        # Tags parsing for name and owner
                        name = inst_id
                        owner = account_id
                        tags = inst.get('Tags', [])
                        for t in tags:
                            if t['Key'] == 'Name':
                                name = t['Value']
                            elif t['Key'] == 'Owner':
                                owner = t['Value']

                        # Security groups
                        sg_names = [sg['GroupName'] for sg in inst.get('SecurityGroups', [])]

                        instances.append({
                            "id": inst_id,
                            "name": name,
                            "type": "EC2",
                            "region": region,
                            "riskScore": 0,  # Calculated downstream
                            "status": "active" if state == "running" else "stopped",
                            "owner": owner,
                            "arn": f"arn:aws:ec2:{region}:{account_id}:instance/{inst_id}",
                            "details": {
                                "public_ip": public_ip,
                                "private_ip": private_ip,
                                "iam_role_name": iam_role_name,
                                "instance_type": inst_type,
                                "security_groups": sg_names
                            }
                        })
            except Exception as e:
                logger.debug(f"Failed to fetch EC2 instances in region {region}: {str(e)}")

        logger.info(f"EC2 Collector: Discovered {len(instances)} instances across all regions")
    except Exception as e:
        logger.error(f"EC2 Collector failed to describe instances: {str(e)}")
    return instances
