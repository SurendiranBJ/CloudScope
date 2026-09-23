import logging
import concurrent.futures
import time
from typing import Dict, List, Any
from app.services.aws.session import get_aws_session, get_account_id, get_boto_config
from app.services.aws.region_cache import get_all_regions, make_region_sessions, RegionalCollectionResult

logger = logging.getLogger("scanner")

def is_running_ec2(inst: Dict[str, Any]) -> bool:
    """Determine whether an EC2 instance dictionary represents an active running instance.
    Security view must contain ONLY instances where state == 'running'.
    Explicitly excludes stopped, stopping, shutting-down, terminated.
    """
    state_val = inst.get("State") or inst.get("state")
    if isinstance(state_val, dict):
        raw_state = (state_val.get("Name") or "").lower().strip()
    else:
        raw_state = (
            state_val
            or inst.get("instance_state")
            or inst.get("details", {}).get("state")
            or inst.get("details", {}).get("instance_state")
            or ""
        )
        if isinstance(raw_state, dict):
            raw_state = raw_state.get("Name", "")
        raw_state = str(raw_state).lower().strip()
    if raw_state:
        return raw_state == "running"
    status = (inst.get("status") or "").lower().strip()
    return status == "active"

def collect_ec2_instances() -> RegionalCollectionResult:
    instances: List[Dict[str, Any]] = []
    regional_status: Dict[str, str] = {}
    successful_regions: List[str] = []
    failed_regions: List[str] = []

    try:
        account_id = get_account_id()
        regions = get_all_regions()
        region_sessions = make_region_sessions(regions)

        def fetch_region_ec2(region_name: str):
            start = time.time()
            region_instances = []
            try:
                client = region_sessions[region_name].client('ec2', region_name=region_name, config=get_boto_config())
                paginator = client.get_paginator('describe_instances')
                for page in paginator.paginate():
                    for reservation in page.get('Reservations', []):
                        for inst in reservation.get('Instances', []):
                            inst_id = inst['InstanceId']
                            state = inst.get('State', {}).get('Name', 'unknown')
                            public_ip = inst.get('PublicIpAddress', 'None')
                            private_ip = inst.get('PrivateIpAddress', 'None')
                            inst_type = inst.get('InstanceType', 'unknown')

                            iam_profile_arn = inst.get('IamInstanceProfile', {}).get('Arn', 'None')
                            iam_role_name = 'None'
                            if iam_profile_arn != 'None':
                                iam_role_name = iam_profile_arn.split('/')[-1]

                            # Name tag can be used for display label, but instance_id is stable conceptual ID
                            name = inst_id
                            owner = account_id
                            tags = inst.get('Tags', [])
                            for t in tags:
                                if t.get('Key') == 'Name':
                                    name = t.get('Value') or inst_id
                                elif t.get('Key') == 'Owner':
                                    owner = t.get('Value') or account_id

                            sg_names = [sg.get('GroupName', '') for sg in inst.get('SecurityGroups', []) if sg.get('GroupName')]

                            inst_arn = f"arn:aws:ec2:{region_name}:{account_id}:instance/{inst_id}"

                            region_instances.append({
                                "id": inst_id,
                                "instance_id": inst_id,
                                "name": name,
                                "type": "EC2",
                                "region": region_name,
                                "riskScore": 0,
                                "state": state,
                                "instance_state": state,
                                "status": "active" if state == "running" else "stopped",
                                "owner": owner,
                                "arn": inst_arn,
                                "instance_type": inst_type,
                                "private_ip": private_ip,
                                "public_ip": public_ip,
                                "security_groups": sg_names,
                                "iam_role_name": iam_role_name,
                                "iam_profile_arn": iam_profile_arn,
                                "details": {
                                    "state": state,
                                    "instance_state": state,
                                    "public_ip": public_ip,
                                    "private_ip": private_ip,
                                    "iam_role_name": iam_role_name,
                                    "iam_profile_arn": iam_profile_arn,
                                    "instance_type": inst_type,
                                    "security_groups": sg_names
                                }
                            })

                elapsed = time.time() - start
                st = "SUCCESS_WITH_DATA" if len(region_instances) > 0 else "SUCCESS_EMPTY"
                logger.info(f"EC2 collection for region {region_name} completed in {elapsed:.2f}s ({st}, {len(region_instances)} instances)")
                return region_name, st, region_instances
            except Exception as e:
                elapsed = time.time() - start
                err_st = f"FAILED: {e}"
                logger.warning(f"EC2 collection for region {region_name} failed in {elapsed:.2f}s: {e}")
                return region_name, err_st, []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for r_name, r_status, r_items in executor.map(fetch_region_ec2, regions):
                regional_status[r_name] = r_status
                if r_status.startswith("FAILED"):
                    failed_regions.append(r_name)
                else:
                    successful_regions.append(r_name)
                    instances.extend(r_items)

        logger.info(
            f"EC2 Collector: Discovered {len(instances)} instances across {len(successful_regions)} successful regions "
            f"({len(failed_regions)} failed regions)"
        )
        return RegionalCollectionResult(
            items=instances,
            regional_status=regional_status,
            successful_regions=successful_regions,
            failed_regions=failed_regions
        )
    except Exception as e:
        logger.error(f"EC2 Collector top-level failed: {e}")
        raise e
