"""Inventory AWS resources used by CloudScope's authorization and attack graph."""

import concurrent.futures
import logging
import time
from typing import Any, Dict, List
from botocore.config import Config

from app.services.aws.region_cache import RegionalCollectionResult, get_all_regions, make_region_sessions
from app.services.aws.session import get_boto_config, get_account_id

logger = logging.getLogger("scanner")


def _collect_by_region(service_name: str, collect_region) -> RegionalCollectionResult:
    regions = get_all_regions()
    sessions = make_region_sessions(regions)
    items: List[Dict[str, Any]] = []
    regional_status: Dict[str, str] = {}
    successful_regions: List[str] = []
    failed_regions: List[str] = []

    def run(region: str):
        try:
            session = sessions[region]
            found = collect_region(session, region)
            return region, "success" if found else "empty", found
        except Exception as exc:
            logger.warning("%s inventory failed in %s: %s", service_name, region, exc)
            return region, "failed", []

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        for region, status, found in executor.map(run, regions):
            regional_status[region] = status
            if status == "failed":
                failed_regions.append(region)
            else:
                successful_regions.append(region)
                items.extend(found)
    return RegionalCollectionResult(items, regional_status, successful_regions, failed_regions)


def collect_ecr_repositories() -> RegionalCollectionResult:
    account_id = get_account_id()

    def collect(session, region):
        client = session.client("ecr", region_name=region, config=get_boto_config())
        result = []
        for page in client.get_paginator("describe_repositories").paginate():
            for repo in page.get("repositories", []):
                resource_policy = None
                policy_status = "NO_POLICY"
                try:
                    policy_response = client.get_repository_policy(repositoryName=repo["repositoryName"])
                    resource_policy = policy_response.get("policyText")
                    policy_status = "COLLECTED" if resource_policy else "NO_POLICY"
                except Exception as exc:
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                    policy_status = "NO_POLICY" if code == "RepositoryPolicyNotFoundException" else "ACCESS_DENIED" if code in {"AccessDeniedException", "AccessDenied"} else "ERROR"
                result.append({
                    "id": repo["repositoryName"],
                    "name": repo["repositoryName"], "type": "ECR",
                    "arn": repo.get("repositoryArn", f"arn:aws:ecr:{region}:{account_id}:repository/{repo['repositoryName']}"),
                    "region": region, "owner": account_id,
                    "details": {"repository_uri": repo.get("repositoryUri"), "image_tag_mutability": repo.get("imageTagMutability"), "resource_policy": resource_policy, "resource_policy_status": policy_status},
                })
        return result

    return _collect_by_region("ECR", collect)


def collect_codecommit_repositories() -> RegionalCollectionResult:
    account_id = get_account_id()

    def collect(session, region):
        client = session.client("codecommit", region_name=region, config=get_boto_config())
        result = []
        paginator = client.get_paginator("list_repositories")
        for page in paginator.paginate():
            for item in page.get("repositories", []):
                name = item["repositoryName"]
                try:
                    repo = client.get_repository(repositoryName=name).get("repositoryMetadata", {})
                except Exception:
                    repo = {}
                arn = repo.get("Arn", f"arn:aws:codecommit:{region}:{account_id}:{name}")
                result.append({
                    "id": name, "name": name, "type": "CodeCommit", "arn": arn,
                    "region": region, "owner": account_id,
                    "details": {"repository_id": item.get("repositoryId"), "default_branch": repo.get("defaultBranch"), "clone_url_http": repo.get("cloneUrlHttp")},
                })
        return result

    return _collect_by_region("CodeCommit", collect)


def collect_messaging_and_workflow_resources() -> Dict[str, RegionalCollectionResult]:
    """Collect SQS, SNS, KMS, EKS and Step Functions metadata and policy evidence.

    This deliberately collects configuration and policy documents only; it never
    reads queue messages, topic payloads, state-machine input, or key material.
    """
    started_at = time.perf_counter()
    regions = get_all_regions()
    sessions = make_region_sessions(regions)
    kinds = ("SQS", "SNS", "KMS", "EKS", "StepFunctions")
    results = {kind: [] for kind in kinds}
    statuses = {kind: {} for kind in kinds}
    failures = {kind: [] for kind in kinds}
    successes = {kind: [] for kind in kinds}

    def collect(kind: str, region: str):
        session = sessions[region]
        client_name = {"SQS": "sqs", "SNS": "sns", "KMS": "kms", "EKS": "eks", "StepFunctions": "stepfunctions"}[kind]
        client = session.client(
            client_name,
            region_name=region,
            config=Config(connect_timeout=2, read_timeout=5, retries={"total_max_attempts": 1}),
        )
        found = []
        if kind == "SQS":
            urls = [url for page in client.get_paginator("list_queues").paginate() for url in page.get("QueueUrls", [])]
            for url in urls:
                attrs = client.get_queue_attributes(QueueUrl=url, AttributeNames=["All"]).get("Attributes", {})
                name = url.rsplit("/", 1)[-1]
                arn = attrs.get("QueueArn", "")
                found.append({"id": arn or url, "name": name, "type": kind, "arn": arn, "region": region, "owner": arn.split(":")[4] if arn else "", "details": {"queue_url": url, "resource_policy": attrs.get("Policy"), "resource_policy_status": "COLLECTED" if attrs.get("Policy") else "NO_POLICY", "kms_master_key_id": attrs.get("KmsMasterKeyId")}})
        elif kind == "SNS":
            topics = [arn for page in client.get_paginator("list_topics").paginate() for arn in page.get("Topics", [])]
            for arn in topics:
                attrs = client.get_topic_attributes(TopicArn=arn).get("Attributes", {})
                found.append({"id": arn, "name": arn.rsplit(":", 1)[-1], "type": kind, "arn": arn, "region": region, "owner": attrs.get("Owner", ""), "details": {"resource_policy": attrs.get("Policy"), "resource_policy_status": "COLLECTED" if attrs.get("Policy") else "NO_POLICY", "kms_master_key_id": attrs.get("KmsMasterKeyId")}})
        elif kind == "KMS":
            key_ids = [item["KeyId"] for page in client.get_paginator("list_keys").paginate() for item in page.get("Keys", [])]
            for key_id in key_ids:
                meta = client.describe_key(KeyId=key_id).get("KeyMetadata", {})
                if meta.get("KeyManager") != "CUSTOMER":
                    continue
                arn = meta.get("Arn", "")
                policy, policy_status = None, "ERROR"
                try:
                    policy = client.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy")
                    policy_status = "COLLECTED" if policy else "NO_POLICY"
                except Exception as exc:
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                    policy_status = "ACCESS_DENIED" if code in {"AccessDeniedException", "AccessDenied"} else "ERROR"
                found.append({"id": arn or key_id, "name": meta.get("Description") or key_id, "type": kind, "arn": arn, "region": region, "owner": meta.get("AWSAccountId", ""), "details": {"key_id": key_id, "key_state": meta.get("KeyState"), "key_usage": meta.get("KeyUsage"), "resource_policy": policy, "resource_policy_status": policy_status}})
        elif kind == "EKS":
            names = [name for page in client.get_paginator("list_clusters").paginate() for name in page.get("clusters", [])]
            for name in names:
                cluster = client.describe_cluster(name=name).get("cluster", {})
                arn = cluster.get("arn", "")
                found.append({"id": arn or name, "name": name, "type": kind, "arn": arn, "region": region, "owner": arn.split(":")[4] if arn else "", "details": {"status": cluster.get("status"), "version": cluster.get("version"), "role_arn": cluster.get("roleArn"), "endpoint": cluster.get("endpoint")}})
        else:
            machines = [item for page in client.get_paginator("list_state_machines").paginate() for item in page.get("stateMachines", []) if item.get("stateMachineArn")]
            for item in machines:
                arn = item["stateMachineArn"]
                machine = client.describe_state_machine(stateMachineArn=arn)
                found.append({"id": arn, "name": machine.get("name", arn.rsplit(":", 1)[-1]), "type": kind, "arn": arn, "region": region, "owner": arn.split(":")[4] if len(arn.split(":")) > 4 else "", "details": {"state_machine_type": machine.get("type"), "status": machine.get("status"), "role_arn": machine.get("roleArn")}})
        return found

    def collect_region(region: str):
        region_results = {}
        for kind in kinds:
            try:
                found = collect(kind, region)
                region_results[kind] = (found, None)
            except Exception as exc:
                region_results[kind] = ([], exc)
        return region, region_results

    # Keep the five service checks for each region together. This lets all
    # regions progress at once instead of queuing 90 separate service-region
    # jobs through a small pool.
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(18, max(1, len(regions)))) as executor:
        futures = {executor.submit(collect_region, region): region for region in regions}
        for future in concurrent.futures.as_completed(futures):
            region = futures[future]
            try:
                region, region_results = future.result()
                for kind, (found, error) in region_results.items():
                    if error:
                        logger.warning("%s inventory failed in %s: %s", kind, region, error)
                        statuses[kind][region] = "failed"
                        failures[kind].append(region)
                        continue
                    results[kind].extend(found)
                    statuses[kind][region] = "success" if found else "empty"
                    successes[kind].append(region)
            except Exception as exc:
                logger.warning("Extended AWS inventory failed in %s: %s", region, exc)
                for kind in kinds:
                    statuses[kind][region] = "failed"
                    failures[kind].append(region)

    collected = {kind: RegionalCollectionResult(results[kind], statuses[kind], successes[kind], failures[kind]) for kind in kinds}
    logger.info(
        "Extended AWS inventory completed in %.2fs across %d region(s) (%s)",
        time.perf_counter() - started_at,
        len(regions),
        ", ".join(f"{kind}: {len(collected[kind].items)}" for kind in kinds),
    )
    return collected


def collect_ecs_tasks() -> RegionalCollectionResult:
    def collect(session, region):
        client = session.client("ecs", region_name=region, config=get_boto_config())
        result = []
        cluster_arns = [arn for page in client.get_paginator("list_clusters").paginate() for arn in page.get("clusterArns", [])]
        task_defs: Dict[str, Dict[str, Any]] = {}
        for cluster_arn in cluster_arns:
            task_arns = [arn for page in client.get_paginator("list_tasks").paginate(cluster=cluster_arn, desiredStatus="RUNNING") for arn in page.get("taskArns", [])]
            for offset in range(0, len(task_arns), 100):
                response = client.describe_tasks(cluster=cluster_arn, tasks=task_arns[offset:offset + 100])
                for task in response.get("tasks", []):
                    task_def_arn = task.get("taskDefinitionArn", "")
                    if task_def_arn and task_def_arn not in task_defs:
                        try:
                            task_defs[task_def_arn] = client.describe_task_definition(taskDefinition=task_def_arn).get("taskDefinition", {})
                        except Exception:
                            task_defs[task_def_arn] = {}
                    task_def = task_defs.get(task_def_arn, {})
                    task_name = task.get("taskArn", "").rsplit("/", 1)[-1]
                    result.append({
                        "id": task.get("taskArn", task_name), "name": task_name, "type": "ECS",
                        "arn": task.get("taskArn", ""), "region": region,
                        "status": task.get("lastStatus", "UNKNOWN"),
                        "details": {
                            "cluster_arn": cluster_arn, "task_definition_arn": task_def_arn,
                            "task_role_arn": task_def.get("taskRoleArn", ""),
                            "execution_role_arn": task_def.get("executionRoleArn", ""),
                            "task_role_name": task_def.get("taskRoleArn", "").rsplit("/", 1)[-1],
                            "images": sorted({c.get("image", "") for c in task_def.get("containerDefinitions", []) if c.get("image")}),
                            "enable_execute_command": task.get("enableExecuteCommand", False),
                        },
                    })
        return result

    return _collect_by_region("ECS", collect)
