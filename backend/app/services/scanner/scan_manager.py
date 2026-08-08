import time
import logging
from datetime import datetime
from app.services.scanner.inventory import AWSInventory
from app.services.aws import (
    iam_service,
    ec2_service,
    s3_service,
    lambda_service,
    secrets_service,
    access_analyzer_service,
    cloudtrail_service
)
from app.services.attack import risk_engine, path_engine
from app.services.graph import graph_builder, graph_loader
from app.database import execute_write
from app.cache import cache

logger = logging.getLogger("scanner")


def _generate_recommendations(inventory, attack_paths) -> list:
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

    # If no findings, add a positive recommendation
    if not recommendations:
        recommendations.append({
            "title": "Security Posture Looks Good",
            "desc": "No critical findings detected in this scan. Continue monitoring and enforcing least-privilege access."
        })

    return recommendations


def _compute_security_score(inventory, critical_risks_count, attack_paths_count) -> int:
    """Compute a dynamic security score from 0-100 based on actual findings."""
    score = 100

    # Deduct for users without MFA (up to -20)
    no_mfa = sum(1 for u in inventory.users if not u.get('mfaEnabled', True))
    total_users = max(len(inventory.users), 1)
    mfa_penalty = min(20, int((no_mfa / total_users) * 20))
    score -= mfa_penalty

    # Deduct for critical risks (up to -25)
    score -= min(25, critical_risks_count * 5)

    # Deduct for attack paths (up to -15)
    score -= min(15, attack_paths_count * 3)

    # Deduct for public S3 buckets (up to -15)
    public_s3 = sum(1 for s in inventory.s3 if not s.get('details', {}).get('public_blocked', True))
    score -= min(15, public_s3 * 5)

    # Deduct for unrotated secrets (up to -10)
    no_rotation = sum(1 for s in inventory.secrets if not s.get('details', {}).get('rotation_enabled', False))
    score -= min(10, no_rotation * 3)

    # Deduct for public EC2 instances (up to -10)
    public_ec2 = sum(1 for e in inventory.ec2 if e.get('details', {}).get('public_ip', 'None') != 'None')
    score -= min(10, public_ec2 * 2)

    # Deduct for inactive users (up to -5)
    inactive = sum(1 for u in inventory.users if u.get('lastActive') == 'Never')
    score -= min(5, inactive)

    return max(0, score)


def _generate_risk_issue(item) -> str:
    """Generate a specific risk issue description based on the actual resource type and findings."""
    item_type = item.get('type', '')
    name = item.get('name') or item.get('username') or 'Unknown'

    if 'user' in item.get('arn', '').lower() or item_type == 'User':
        issues = []
        if not item.get('mfaEnabled', True):
            issues.append("MFA not enabled")
        policies = item.get('policies', [])
        admin_policies = [p for p in policies if 'admin' in p.lower()]
        if admin_policies:
            issues.append(f"admin-level policies: {', '.join(admin_policies[:2])}")
        if not issues:
            issues.append("elevated risk score from policy configuration")
        return f"User '{name}': {'; '.join(issues)}"

    elif 'role' in item.get('arn', '').lower() or item_type == 'Role':
        if 'admin' in name.lower():
            return f"Role '{name}': has administrative access configuration"
        return f"Role '{name}': elevated privilege trust policy"

    elif item_type == 'S3':
        issues = []
        details = item.get('details', {})
        if not details.get('public_blocked', True):
            issues.append("public access not blocked")
        if not details.get('encrypted', True):
            issues.append("server-side encryption disabled")
        if not issues:
            issues.append("elevated risk from access configuration")
        return f"S3 bucket '{name}': {'; '.join(issues)}"

    elif item_type == 'Secrets':
        if not item.get('details', {}).get('rotation_enabled', False):
            return f"Secret '{name}': automatic rotation not enabled"
        return f"Secret '{name}': elevated risk configuration"

    elif item_type == 'EC2':
        if item.get('details', {}).get('public_ip', 'None') != 'None':
            return f"EC2 '{name}': publicly accessible (IP: {item['details']['public_ip']})"
        return f"EC2 '{name}': elevated risk from instance profile configuration"

    return f"Resource '{name}': elevated risk score detected"


def _generate_recommendation(item) -> str:
    """Generate a specific recommendation for a risk finding."""
    item_type = item.get('type', '')

    if 'user' in item.get('arn', '').lower() or item_type == 'User':
        if not item.get('mfaEnabled', True):
            return "Enable MFA immediately and review attached policies for least-privilege compliance"
        return "Review and reduce attached policies to minimum required permissions"

    elif 'role' in item.get('arn', '').lower() or item_type == 'Role':
        return "Restrict AssumeRole trust policy principals and add MFA conditions"

    elif item_type == 'S3':
        if not item.get('details', {}).get('public_blocked', True):
            return "Enable S3 Block Public Access and review bucket policy"
        return "Enable SSE encryption and review bucket access controls"

    elif item_type == 'Secrets':
        return "Enable automatic secret rotation and restrict access policies"

    elif item_type == 'EC2':
        return "Review security groups, restrict public access, and upgrade to IMDSv2"

    return "Apply least-privilege access controls"


class ScanManager:
    def __init__(self):
        self.inventory = AWSInventory()
        self.is_running = False

    def run_scan(self) -> dict:
        if self.is_running:
            logger.warning("Scan sync already in progress. Skipping duplicate request.")
            return {"status": "skipped", "message": "Scan already running"}

        self.is_running = True
        start_time = time.time()
        logger.info("Central Orchestrator starting AWS scan sync sequence")

        try:
            self.inventory.clear()

            # 1. AWS API Data Collection
            self.inventory.users = iam_service.collect_users()
            self.inventory.groups = iam_service.collect_groups()
            self.inventory.roles = iam_service.collect_roles()
            self.inventory.policies = iam_service.collect_policies()

            self.inventory.ec2 = ec2_service.collect_ec2_instances()
            self.inventory.s3 = s3_service.collect_s3_buckets()
            self.inventory.lambdas = lambda_service.collect_lambda_functions()
            self.inventory.secrets = secrets_service.collect_secrets()
            self.inventory.findings = access_analyzer_service.collect_access_analyzer_findings()
            self.inventory.alerts = cloudtrail_service.collect_recent_alerts()

            # 2. Risk Engine Scoring
            for u in self.inventory.users:
                u['riskScore'] = risk_engine.score_user_risk(u)
            for r in self.inventory.roles:
                r['riskScore'] = risk_engine.score_role_risk(r)
            for s in self.inventory.s3:
                s['riskScore'] = risk_engine.score_resource_risk(s)
            for e in self.inventory.ec2:
                e['riskScore'] = risk_engine.score_resource_risk(e)
            for sec in self.inventory.secrets:
                sec['riskScore'] = risk_engine.score_resource_risk(sec)

            # 3. Build Neo4j database graph
            try:
                graph_builder.build_graph_in_neo4j(self.inventory)
            except Exception as db_err:
                logger.warning(f"Neo4j database write failed, skipping sync: {str(db_err)}")

            # 4. Load in-memory NetworkX directed graph
            try:
                G = graph_loader.load_graph_from_neo4j()
                if G.number_of_nodes() == 0:
                    raise Exception("Empty graph from Neo4j")
            except Exception as loader_err:
                logger.warning(f"Neo4j graph load failed, building local NetworkX model: {str(loader_err)}")
                G = graph_loader.build_local_graph(self.inventory)

            # 5. Mappings & Paths Calculation
            attack_paths = path_engine.find_attack_paths(G)

            duration = round(time.time() - start_time, 2)
            logger.info(f"AWS Scan completed in {duration}s")

            # 6. Record ScanHistory node in Neo4j
            scan_timestamp = datetime.utcnow().isoformat() + "Z"
            resources_count = len(self.inventory.ec2) + len(self.inventory.s3) + len(self.inventory.lambdas) + len(self.inventory.secrets)
            nodes_count = G.number_of_nodes()
            edges_count = G.number_of_edges()

            # Compute all risk items across all resource types
            all_scored_items = self.inventory.users + self.inventory.roles + self.inventory.s3 + self.inventory.ec2 + self.inventory.secrets

            # Categorize by risk level
            critical_items = [x for x in all_scored_items if x.get('riskScore', 0) >= 80]
            high_items = [x for x in all_scored_items if 60 <= x.get('riskScore', 0) < 80]
            medium_items = [x for x in all_scored_items if 40 <= x.get('riskScore', 0) < 60]
            low_items = [x for x in all_scored_items if 0 < x.get('riskScore', 0) < 40]

            risks_count = len(critical_items)

            try:
                execute_write(
                    "CREATE (n:ScanHistory {timestamp: $ts, duration: $dur, resources_found: $res, risks_found: $risks, nodes: $nodes, edges: $edges})",
                    {
                        "ts": scan_timestamp,
                        "dur": duration,
                        "res": resources_count,
                        "risks": risks_count,
                        "nodes": nodes_count,
                        "edges": edges_count
                    }
                )
            except Exception as hist_err:
                logger.warning(f"Neo4j ScanHistory creation failed: {str(hist_err)}")

            # 7. Refresh/Invalidate Redis Cache keys
            cache.set("v1:users", self.inventory.users)
            cache.set("v1:roles", self.inventory.roles)
            cache.set("v1:policies", self.inventory.policies)
            cache.set("v1:resources", self.inventory.users + self.inventory.roles + self.inventory.ec2 + self.inventory.s3 + self.inventory.lambdas + self.inventory.secrets)
            cache.set("v1:alerts", self.inventory.alerts)
            cache.set("v1:attack-paths", attack_paths)

            # Format Cytoscape graph json response
            cytoscape_elements = []
            for nid, attr in G.nodes(data=True):
                cytoscape_elements.append({
                    "data": {
                        "id": nid,
                        "label": attr.get('label', nid),
                        "type": attr.get('type', 'Resource'),
                        "riskScore": attr.get('riskScore', 0),
                        "arn": attr.get('arn', ''),
                        "description": attr.get('description', '')
                    }
                })
            for s, t, attr in G.edges(data=True):
                cytoscape_elements.append({
                    "data": {
                        "id": f"e-{s}-{t}",
                        "source": s,
                        "target": t,
                        "label": attr.get('label', 'CONNECTED_TO')
                    }
                })
            cache.set("v1:graph", cytoscape_elements)

            # Format Critical Risk Findings with specific issues
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
                for x in all_scored_items if x.get('riskScore', 0) >= 60
            ]
            # Sort by risk score descending
            critical_risks.sort(key=lambda x: x['riskScore'], reverse=True)
            cache.set("v1:risks", critical_risks)

            # Compute dynamic security score
            security_score = _compute_security_score(self.inventory, len(critical_items), len(attack_paths))

            # Generate dynamic recommendations
            recommendations = _generate_recommendations(self.inventory, attack_paths)

            # Format Dashboard Data — ALL values computed dynamically
            dashboard_data = {
                "securityScore": f"{security_score} / 100",
                "stats": {
                    "users": len(self.inventory.users),
                    "roles": len(self.inventory.roles),
                    "policies": len(self.inventory.policies),
                    "risks": len(critical_risks),
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
                "criticalPaths": attack_paths[:3],
                "recommendations": recommendations[:5],
                "lastScan": {
                    "timestamp": scan_timestamp,
                    "duration_seconds": duration,
                    "resources_found": resources_count,
                    "risks_found": risks_count,
                    "graph_nodes_count": nodes_count,
                    "graph_edges_count": edges_count
                }
            }
            cache.set("v1:dashboard", dashboard_data)

            self.is_running = False
            return {
                "status": "success",
                "timestamp": scan_timestamp,
                "duration": duration,
                "resources": resources_count,
                "risks": risks_count
            }

        except Exception as e:
            self.is_running = False
            logger.error(f"Scan Manager Orchestrator failed: {str(e)}")
            return {"status": "error", "message": str(e)}


# Export singleton
scan_manager = ScanManager()
