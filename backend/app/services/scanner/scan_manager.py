import time
import logging
import threading
import concurrent.futures
from datetime import datetime
from typing import Dict, Any, List
from app.services.scanner.inventory import AWSInventory
from app.services.aws import (
    iam_service,
    ec2_service,
    s3_service,
    lambda_service,
    secrets_service,
    access_analyzer_service,
    cloudtrail_service,
    rds_service,
    dynamodb_service
)
from app.services.aws.session import get_aws_diagnostic_info, get_account_id
from app.services.aws.region_cache import clear_region_cache, get_all_regions
from app.services.attack import risk_engine, path_engine, cloudtrail_correlator
from app.services.graph import graph_builder, graph_loader
from app.database import execute_write
from app.cache import cache

logger = logging.getLogger("scanner")


def _generate_recommendations(inventory: AWSInventory, attack_paths: list) -> list:
    """Generate actionable security recommendations based on actual AWS findings."""
    recommendations = []

    # Check for users without MFA
    no_mfa_users = [u for u in inventory.users if not u.get('mfaEnabled', True)]
    if no_mfa_users:
        names = ", ".join(u['name'] for u in no_mfa_users[:3])
        suffix = f" and {len(no_mfa_users) - 3} more" if len(no_mfa_users) > 3 else ""
        recommendations.append({
            "title": f"Enable MFA for {len(no_mfa_users)} IAM User{'s' if len(no_mfa_users) != 1 else ''}",
            "desc": f"Users without MFA: {names}{suffix}. Enable MFA to prevent credential-based account takeover."
        })

    # Check for public S3 buckets
    public_buckets = [s for s in inventory.s3 if not s.get('details', {}).get('public_blocked', True)]
    if public_buckets:
        names = ", ".join(s['name'] for s in public_buckets[:3])
        recommendations.append({
            "title": f"Block Public Access on {len(public_buckets)} S3 Bucket{'s' if len(public_buckets) != 1 else ''}",
            "desc": f"Buckets without public access block: {names}. Enable S3 Block Public Access to prevent data exposure."
        })

    # Check for unencrypted S3 buckets
    unencrypted_buckets = [s for s in inventory.s3 if not s.get('details', {}).get('encrypted', True)]
    if unencrypted_buckets:
        names = ", ".join(s['name'] for s in unencrypted_buckets[:3])
        recommendations.append({
            "title": f"Enable Encryption on {len(unencrypted_buckets)} S3 Bucket{'s' if len(unencrypted_buckets) != 1 else ''}",
            "desc": f"Buckets without encryption: {names}. Enable SSE-S3 or SSE-KMS to protect data at rest."
        })

    # Check for secrets without rotation
    no_rotation_secrets = [s for s in inventory.secrets if not s.get('details', {}).get('rotation_enabled', False)]
    if no_rotation_secrets:
        names = ", ".join(s['name'] for s in no_rotation_secrets[:3])
        recommendations.append({
            "title": f"Enable Rotation for {len(no_rotation_secrets)} Secret{'s' if len(no_rotation_secrets) != 1 else ''}",
            "desc": f"Secrets without rotation: {names}. Configure automatic rotation to reduce credential exposure risk."
        })

    # Check for EC2 instances with public IPs
    public_ec2 = [e for e in inventory.ec2 if e.get('details', {}).get('public_ip', 'None') != 'None']
    if public_ec2:
        names = ", ".join(e['name'] for e in public_ec2[:3])
        recommendations.append({
            "title": f"Review {len(public_ec2)} Publicly Accessible EC2 Instance{'s' if len(public_ec2) != 1 else ''}",
            "desc": f"Instances with public IPs: {names}. Verify these need public access and ensure security groups are restrictive."
        })

    # Check for inactive users
    inactive_users = [u for u in inventory.users if u.get('lastActive') == 'Never']
    if inactive_users:
        names = ", ".join(u['name'] for u in inactive_users[:3])
        recommendations.append({
            "title": f"Review {len(inactive_users)} Inactive IAM User{'s' if len(inactive_users) != 1 else ''}",
            "desc": f"Users with no recorded activity: {names}. Consider removing unused credentials to reduce attack surface."
        })

    # Check for critical attack paths
    critical_paths = [p for p in attack_paths if p.get('severity') == 'critical']
    if critical_paths:
        recommendations.append({
            "title": f"Mitigate {len(critical_paths)} Critical Attack Path{'s' if len(critical_paths) != 1 else ''}",
            "desc": f"Critical lateral movement paths detected. Apply least-privilege policies and restrict AssumeRole trust relationships."
        })

    if not recommendations:
        recommendations.append({
            "title": "Security Posture Verification Complete",
            "desc": "All tested security baselines verified. Continue monitoring CloudTrail activity and least-privilege enforcement."
        })

    return recommendations


def _generate_risk_issue(item: dict) -> str:
    """Generate a specific, descriptive issue string for a risky item."""
    factors = item.get('riskAssessment', {}).get('factors', [])
    if factors:
        return "; ".join(f['reason'] for f in factors)

    itype = item.get('type', '')
    if itype == 'User':
        issues = []
        if not item.get('mfaEnabled', True):
            issues.append("MFA not enabled")
        return "; ".join(issues) if issues else "Elevated user permissions"

    elif itype == 'Role':
        return "Elevated role privileges or broad trust policy"

    elif itype == 'S3':
        details = item.get('details', {})
        issues = []
        if not details.get('public_blocked', True):
            issues.append("Public access not blocked (potential data exposure)")
        if not details.get('encrypted', True):
            issues.append("Server-side encryption not configured")
        return "; ".join(issues) if issues else "S3 configuration review recommended"

    elif itype == 'Secrets':
        return "Automatic secret rotation is not enabled"

    elif itype == 'EC2':
        details = item.get('details', {})
        if details.get('public_ip', 'None') != 'None':
            return f"Publicly accessible instance ({details.get('public_ip')})"
        return "Compute instance security group review recommended"

    elif itype == 'RDS':
        details = item.get('details', {})
        issues = []
        if details.get('publicly_accessible', False):
            issues.append("Publicly accessible database")
        if not details.get('storage_encrypted', True):
            issues.append("Storage volume unencrypted")
        return "; ".join(issues) if issues else "Database security configuration review recommended"

    return "Configuration risk detected"


def _generate_recommendation(item: dict) -> str:
    """Generate an actionable remediation recommendation string for a risky item."""
    itype = item.get('type', '')
    name = item.get('name') or item.get('username') or 'Resource'

    if itype == 'User':
        if not item.get('mfaEnabled', True):
            return f"Enforce Multi-Factor Authentication (MFA) immediately for user '{name}'."
        return f"Review attached policies on user '{name}' and apply least-privilege scoping."

    elif itype == 'Role':
        return f"Review the AssumeRole trust policy on role '{name}' and restrict the Principal to specific trusted ARNs."

    elif itype == 'S3':
        details = item.get('details', {})
        if not details.get('public_blocked', True):
            return f"Enable S3 Block Public Access on bucket '{name}' to prevent public data exposure."
        return f"Enable default server-side encryption (SSE-S3 or SSE-KMS) on bucket '{name}'."

    elif itype == 'EC2':
        return f"Review security groups for instance '{name}' to restrict inbound access and minimize public exposure."

    elif itype == 'Secrets':
        return f"Configure automatic rotation for secret '{name}' using AWS Secrets Manager rotation lambdas."

    elif itype == 'RDS':
        return f"Disable public accessibility and enable storage encryption for database '{name}'."

    elif itype == 'DynamoDB':
        return f"Enable Point-in-Time Recovery (PITR) for DynamoDB table '{name}'."

    return f"Review the security configuration and apply least-privilege access to '{name}'."


class ScanManager:
    """Central Orchestrator for the unified single continuous scanning pipeline.

    Ordering:
    AWS Collection -> CloudTrail Normalization -> Neo4j Config & Activity Sync
    -> NetworkX Reload -> Attack Path & Correlation Analysis -> Risk Engine -> Cache.
    """

    def __init__(self):
        self.inventory = AWSInventory()
        self._lock = threading.Lock()
        self._is_running = False
        self._scan_started_at: str | None = None
        self._last_result: dict | None = None
        self._service_status: Dict[str, str] = {}

    @property
    def is_running(self) -> bool:
        return self._is_running

    def get_status(self) -> dict:
        """Return current scan status for the frontend to poll."""
        return {
            "is_scanning": self._is_running,
            "started_at": self._scan_started_at,
            "last_result": self._last_result,
            "service_status": self._service_status
        }

    def trigger_async_scan(self) -> dict:
        """Start a scan in a background thread. Returns immediately."""
        if self._is_running:
            return {"status": "already_running", "message": "Scan already in progress"}
        thread = threading.Thread(target=self.run_scan, daemon=True)
        thread.start()
        return {"status": "started", "message": "Scan started in background"}

    def run_scan(self) -> dict:
        if not self._lock.acquire(blocking=False):
            logger.warning("Scan lock held. Skipping duplicate.")
            return {"status": "skipped", "message": "Scan already running"}

        self._is_running = True
        self._scan_started_at = datetime.utcnow().isoformat() + "Z"
        start_time = time.time()
        self._service_status = {}

        logger.info("[INFO] SCAN START: Initializing AWS single continuous security scan")

        try:
            # 0. AWS STS Authentication Check
            aws_diag = get_aws_diagnostic_info()
            if not aws_diag["authenticated"]:
                logger.error(f"[ERROR] AWS Authentication failed: {aws_diag.get('error')}")
                self._last_result = {
                    "status": "failed",
                    "error": f"AWS Authentication failed: {aws_diag.get('error')}",
                    "timestamp": self._scan_started_at
                }
                return self._last_result

            logger.info(
                f"[INFO] AWS AUTHENTICATION: Account={aws_diag['account_id']}, "
                f"ARN={aws_diag['arn']}, Region={aws_diag['region']}"
            )

            self.inventory.clear()
            clear_region_cache()
            scanned_regions = list(get_all_regions())
            logger.info(f"[INFO] Scan regions: {scanned_regions}")

            def run_collector(name, func):
                try:
                    res = func()
                    self._service_status[name] = "SUCCESS"
                    return res
                except Exception as err:
                    logger.error(f"[ERROR] Collector {name} failed: {err}")
                    self._service_status[name] = f"FAILED: {err}"
                    return []

            # 1. AWS API Data Collection (Concurrently)
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_users = executor.submit(run_collector, "IAM_Users", iam_service.collect_users)
                future_groups = executor.submit(run_collector, "IAM_Groups", iam_service.collect_groups)
                future_roles = executor.submit(run_collector, "IAM_Roles", iam_service.collect_roles)
                future_policies = executor.submit(run_collector, "IAM_Policies", iam_service.collect_policies)
                future_ec2 = executor.submit(run_collector, "EC2", ec2_service.collect_ec2_instances)
                future_s3 = executor.submit(run_collector, "S3", s3_service.collect_s3_buckets)
                future_lambdas = executor.submit(run_collector, "Lambda", lambda_service.collect_lambda_functions)
                future_secrets = executor.submit(run_collector, "Secrets", secrets_service.collect_secrets)
                future_rds = executor.submit(run_collector, "RDS", rds_service.collect_rds_instances)
                future_dynamodb = executor.submit(run_collector, "DynamoDB", dynamodb_service.collect_dynamodb_tables)
                future_findings = executor.submit(run_collector, "AccessAnalyzer", access_analyzer_service.collect_access_analyzer_findings)
                future_alerts = executor.submit(run_collector, "CloudTrail", cloudtrail_service.collect_recent_alerts)

                self.inventory.users = future_users.result()
                self.inventory.groups = future_groups.result()
                self.inventory.roles = future_roles.result()
                self.inventory.policies = future_policies.result()
                self.inventory.ec2 = future_ec2.result()
                self.inventory.s3 = future_s3.result()
                self.inventory.lambdas = future_lambdas.result()
                self.inventory.secrets = future_secrets.result()
                self.inventory.rds = future_rds.result()
                self.inventory.dynamodb = future_dynamodb.result()
                self.inventory.findings = future_findings.result()
                self.inventory.alerts = future_alerts.result()

            logger.info(
                f"[INFO] Discovered AWS Resources: Users={len(self.inventory.users)}, "
                f"Roles={len(self.inventory.roles)}, Groups={len(self.inventory.groups)}, "
                f"Policies={len(self.inventory.policies)}, S3={len(self.inventory.s3)}, "
                f"EC2={len(self.inventory.ec2)}, Lambda={len(self.inventory.lambdas)}, "
                f"RDS={len(self.inventory.rds)}, DynamoDB={len(self.inventory.dynamodb)}, "
                f"Secrets={len(self.inventory.secrets)}"
            )

            # 2. Build Policy Document Map (Customer-Managed + Inline + Attached AWS-Managed)
            policy_doc_map = {
                p['name']: p['document']
                for p in self.inventory.policies
            }

            # Inline policy documents
            for u in self.inventory.users:
                for in_name, in_doc in u.get('inlinePolicyDocuments', {}).items():
                    policy_doc_map[in_name] = in_doc
                    self.inventory.policies.append({
                        "name": in_name,
                        "arn": f"arn:aws:iam:inline:{u['name']}:{in_name}",
                        "type": "inline",
                        "document": in_doc,
                        "riskScore": 0
                    })
            for r in self.inventory.roles:
                for in_name, in_doc in r.get('inlinePolicyDocuments', {}).items():
                    policy_doc_map[in_name] = in_doc
                    self.inventory.policies.append({
                        "name": in_name,
                        "arn": f"arn:aws:iam:inline:{r['name']}:{in_name}",
                        "type": "inline",
                        "document": in_doc,
                        "riskScore": 0
                    })
            for g in self.inventory.groups:
                for in_name, in_doc in g.get('inlinePolicyDocuments', {}).items():
                    policy_doc_map[in_name] = in_doc
                    self.inventory.policies.append({
                        "name": in_name,
                        "arn": f"arn:aws:iam:inline:{g['name']}:{in_name}",
                        "type": "inline",
                        "document": in_doc,
                        "riskScore": 0
                    })

            # Fetch AWS-managed policy documents for attached policies
            aws_managed_arns: set = set()
            for u in self.inventory.users:
                aws_managed_arns.update(
                    arn for arn in u.get('attachedPolicyArns', {}).values()
                    if '::aws:policy/' in arn
                )
            for r in self.inventory.roles:
                aws_managed_arns.update(
                    arn for arn in r.get('attachedPolicyArns', {}).values()
                    if '::aws:policy/' in arn
                )
            for g in self.inventory.groups:
                aws_managed_arns.update(
                    arn for arn in g.get('attachedPolicyArns', {}).values()
                    if '::aws:policy/' in arn
                )

            if aws_managed_arns:
                logger.info(f"[INFO] Resolving {len(aws_managed_arns)} attached AWS-managed policy documents")
                managed_docs = iam_service.fetch_managed_policy_documents(aws_managed_arns)
                policy_doc_map.update(managed_docs)
                for pol_name, doc_str in managed_docs.items():
                    if not any(p['name'] == pol_name for p in self.inventory.policies):
                        self.inventory.policies.append({
                            "name": pol_name,
                            "arn": f"arn:aws:iam::aws:policy/{pol_name}",
                            "type": "aws-managed",
                            "document": doc_str,
                            "riskScore": 0
                        })

            # 3. Calculate Deterministic Risk Assessments & Scores
            for u in self.inventory.users:
                eval_res = risk_engine.get_user_risk_assessment(u, policy_doc_map)
                u['riskScore'] = eval_res['score']
                u['riskAssessment'] = eval_res

            for r in self.inventory.roles:
                eval_res = risk_engine.get_role_risk_assessment(r, policy_doc_map)
                r['riskScore'] = eval_res['score']
                r['riskAssessment'] = eval_res

            for s in self.inventory.s3:
                eval_res = risk_engine.get_resource_risk_assessment(s)
                s['riskScore'] = eval_res['score']
                s['riskAssessment'] = eval_res

            for e in self.inventory.ec2:
                eval_res = risk_engine.get_resource_risk_assessment(e)
                e['riskScore'] = eval_res['score']
                e['riskAssessment'] = eval_res

            for sec in self.inventory.secrets:
                eval_res = risk_engine.get_resource_risk_assessment(sec)
                sec['riskScore'] = eval_res['score']
                sec['riskAssessment'] = eval_res

            for rds in self.inventory.rds:
                eval_res = risk_engine.get_resource_risk_assessment(rds)
                rds['riskScore'] = eval_res['score']
                rds['riskAssessment'] = eval_res

            for ddb in self.inventory.dynamodb:
                eval_res = risk_engine.get_resource_risk_assessment(ddb)
                ddb['riskScore'] = eval_res['score']
                ddb['riskAssessment'] = eval_res

            # 4. STEP 1 OF PIPELINE: Neo4j Configuration Sync (Idempotent MERGE, preserves ActivityEvent)
            neo4j_success = False
            try:
                graph_builder.build_graph_in_neo4j(self.inventory)
                neo4j_success = True
            except Exception as db_err:
                logger.warning(f"Neo4j database sync skipped/failed: {db_err}")

            # 5. STEP 2 OF PIPELINE: Load Base NetworkX Graph
            try:
                if neo4j_success:
                    G = graph_loader.load_graph_from_neo4j()
                    if G.number_of_nodes() == 0:
                        G = graph_loader.build_local_graph(self.inventory)
                else:
                    G = graph_loader.build_local_graph(self.inventory)
            except Exception as loader_err:
                logger.warning(f"Neo4j loader exception: {loader_err}. Building local NetworkX model.")
                G = graph_loader.build_local_graph(self.inventory)

            # 6. STEP 3 OF PIPELINE: CloudTrail Activity Normalization & Synchronization into Graph
            correlation_result = cloudtrail_correlator.correlate_activity_with_graph(
                self.inventory.alerts,
                self.inventory,
                G  # Dynamic activity edges added directly to G
            )
            correlated_findings = correlation_result.get("correlated_findings", [])

            nodes_count = G.number_of_nodes()
            edges_count = G.number_of_edges()
            logger.info(f"[INFO] Graph construction complete: {nodes_count} nodes, {edges_count} edges (with dynamic activity)")

            # 7. STEP 4 OF PIPELINE: Attack Path Engine Analysis on Fully Synchronized Graph
            attack_paths = path_engine.find_attack_paths(G)
            logger.info(f"[INFO] Attack Path Engine: {len(attack_paths)} paths detected")

            duration = round(time.time() - start_time, 2)

            # 8. STEP 5 OF PIPELINE: Findings & Severity Groupings
            all_scored_items = (
                self.inventory.users + self.inventory.roles +
                self.inventory.s3 + self.inventory.ec2 +
                self.inventory.secrets + self.inventory.rds +
                self.inventory.dynamodb
            )

            critical_items = [x for x in all_scored_items if x.get('riskScore', 0) >= 80]
            high_items = [x for x in all_scored_items if 60 <= x.get('riskScore', 0) < 80]
            medium_items = [x for x in all_scored_items if 40 <= x.get('riskScore', 0) < 60]
            low_items = [x for x in all_scored_items if 0 < x.get('riskScore', 0) < 40]

            total_findings_count = len(critical_items) + len(high_items) + len(medium_items) + len(low_items)

            # Calculate Global 5-Category Posture Score
            global_posture = risk_engine.compute_global_security_score(
                self.inventory,
                attack_paths,
                self.inventory.alerts
            )
            security_score = global_posture["overall_score"]
            recommendations = _generate_recommendations(self.inventory, attack_paths)

            # 9. Record ScanHistory (Accurate Severity Metrics)
            scan_timestamp = datetime.utcnow().isoformat() + "Z"
            resources_count = (
                len(self.inventory.ec2) + len(self.inventory.s3) +
                len(self.inventory.lambdas) + len(self.inventory.secrets) +
                len(self.inventory.rds) + len(self.inventory.dynamodb)
            )

            try:
                execute_write(
                    """
                    CREATE (n:ScanHistory {
                        timestamp: $ts,
                        duration: $dur,
                        resources_found: $res,
                        total_findings: $total_findings,
                        critical_findings: $crit,
                        high_findings: $high,
                        medium_findings: $med,
                        low_findings: $low,
                        attack_paths: $paths,
                        cloudtrail_events: $ct_events,
                        correlated_findings: $corr,
                        security_score: $score,
                        nodes: $nodes,
                        edges: $edges
                    })
                    """,
                    {
                        "ts": scan_timestamp,
                        "dur": duration,
                        "res": resources_count,
                        "total_findings": total_findings_count,
                        "crit": len(critical_items),
                        "high": len(high_items),
                        "med": len(medium_items),
                        "low": len(low_items),
                        "paths": len(attack_paths),
                        "ct_events": len(self.inventory.alerts),
                        "corr": len(correlated_findings),
                        "score": security_score,
                        "nodes": nodes_count,
                        "edges": edges_count
                    }
                )
            except Exception as hist_err:
                logger.debug(f"Neo4j ScanHistory creation skipped: {hist_err}")

            # 10. STEP 6 OF PIPELINE: Cache Updates
            cache.set("v1:users", self.inventory.users)
            cache.set("v1:roles", self.inventory.roles)
            cache.set("v1:policies", self.inventory.policies)
            cache.set("v1:resources", (
                self.inventory.users + self.inventory.roles +
                self.inventory.ec2 + self.inventory.s3 +
                self.inventory.lambdas + self.inventory.secrets +
                self.inventory.rds + self.inventory.dynamodb
            ))
            cache.set("v1:alerts", self.inventory.alerts)
            cache.set("v1:correlated_risks", correlated_findings)
            cache.set("v1:attack-paths", attack_paths)
            cache.set("v1:global_posture", global_posture)

            # Cytoscape Graph Elements
            cytoscape_elements = []
            role_map = {r['name']: r for r in self.inventory.roles}
            user_map = {u['name']: u for u in self.inventory.users}

            for nid, attr in G.nodes(data=True):
                node_type = attr.get('type', 'Resource')
                label = attr.get('label', nid)
                extra: dict = {}
                if node_type == 'Role':
                    role = role_map.get(label) or role_map.get(nid)
                    if role:
                        extra['trustPolicy'] = role.get('trustPolicy', '')
                elif node_type == 'User':
                    user = user_map.get(label) or user_map.get(nid)
                    if user:
                        extra['policies'] = user.get('policies', [])

                cytoscape_elements.append({
                    "data": {
                        "id": nid,
                        "label": label,
                        "type": node_type,
                        "riskScore": attr.get('riskScore', 0),
                        "arn": attr.get('arn', ''),
                        "description": attr.get('description', ''),
                        **extra
                    }
                })
            for s, t, attr in G.edges(data=True):
                cytoscape_elements.append({
                    "data": {
                        "id": f"e-{s}-{t}",
                        "source": s,
                        "target": t,
                        "label": attr.get('label', 'CONNECTED_TO'),
                        "isActivity": attr.get('is_activity', False),
                        "timestamp": attr.get('timestamp', ''),
                        "sourceIp": attr.get('sourceIp', '')
                    }
                })
            cache.set("v1:graph", cytoscape_elements)

            # Critical Risks Findings list
            critical_risks = [
                {
                    "id": x.get('id', x.get('name', 'unknown')),
                    "identity": x.get('name') or x.get('username') or "unknown",
                    "identityType": x.get('type') or ("User" if "user" in x.get('arn', '').lower() else ("Role" if "role" in x.get('arn', '').lower() else "Resource")),
                    "issue": _generate_risk_issue(x),
                    "severity": "critical" if x.get('riskScore', 0) >= 80 else ("high" if x.get('riskScore', 0) >= 60 else "medium"),
                    "riskScore": x['riskScore'],
                    "recommendation": _generate_recommendation(x)
                }
                for x in all_scored_items if x.get('riskScore', 0) >= 40
            ]
            critical_risks.sort(key=lambda x: x['riskScore'], reverse=True)
            cache.set("v1:risks", critical_risks)

            critical_paths_list = [p for p in attack_paths if p.get('severity') in ['critical', 'high']][:5]
            dashboard_summary = {
                "securityScore": f"{security_score} / 100",
                "stats": {
                    "users": len(self.inventory.users),
                    "roles": len(self.inventory.roles),
                    "policies": len(self.inventory.policies),
                    "risks": len(critical_items) + len(high_items) + len(medium_items),
                    "paths": len(attack_paths),
                    "resources": resources_count
                },
                "riskDistribution": [
                    {"name": "Critical", "value": len(critical_items), "color": "#EF4444"},
                    {"name": "High", "value": len(high_items), "color": "#F59E0B"},
                    {"name": "Medium", "value": len(medium_items), "color": "#3B82F6"},
                    {"name": "Low", "value": len(low_items), "color": "#10B981"}
                ],
                "recentAlerts": self.inventory.alerts[:5],
                "criticalPaths": critical_paths_list,
                "recommendations": [
                    {"title": r.get('title', 'Remediation'), "desc": r.get('description', '')}
                    for r in recommendations[:3]
                ] if recommendations else [
                    {"title": "Enforce Least Privilege", "desc": "Restrict wildcard IAM policies and apply resource-specific ARN constraints."},
                    {"title": "Enable MFA for All Users", "desc": "Enforce hardware or virtual MFA across all administrative and developer user accounts."},
                    {"title": "Block Public S3 Access", "desc": "Enable S3 Block Public Access to prevent accidental internet-wide data exposure."}
                ],
                "lastScan": {
                    "timestamp": scan_timestamp,
                    "duration_seconds": duration,
                    "resources_found": resources_count,
                    "risks_found": total_findings_count,
                    "graph_nodes_count": nodes_count,
                    "graph_edges_count": edges_count,
                    "scanned_regions": scanned_regions
                }
            }
            cache.set("v1:dashboard", dashboard_summary)

            self._last_result = {
                "status": "success",
                "timestamp": scan_timestamp,
                "duration_seconds": duration,
                "nodes_count": nodes_count,
                "edges_count": edges_count,
                "attack_paths_count": len(attack_paths),
                "security_score": security_score,
                "total_findings": total_findings_count,
                "critical_findings": len(critical_items),
                "service_status": self._service_status
            }

            logger.info(
                f"[INFO] SCAN COMPLETE: Duration={duration}s, Nodes={nodes_count}, Edges={edges_count}, "
                f"AttackPaths={len(attack_paths)}, TotalFindings={total_findings_count}, SecurityScore={security_score}/100"
            )

            return self._last_result

        except Exception as e:
            logger.error(f"[ERROR] Scan execution encountered an unexpected failure: {e}", exc_info=True)
            self._last_result = {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            return self._last_result
        finally:
            self._is_running = False
            self._lock.release()


scan_manager = ScanManager()
