import os
import json
import time
import uuid
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
from app.services.findings.finding_service import finding_service
from app.services.attack.policy_evaluator import classify_action_category

logger = logging.getLogger("scanner")

SCAN_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
LAST_SCAN_FILE = os.path.join(SCAN_DATA_DIR, "last_scan.json")


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


CRITICAL_COLLECTORS = {
    "IAM_Users", "IAM_Groups", "IAM_Roles", "IAM_Policies",
    "S3", "EC2", "Lambda", "Secrets", "RDS", "DynamoDB"
}

ALL_COLLECTOR_NAMES = [
    "IAM_Users", "IAM_Groups", "IAM_Roles", "IAM_Policies",
    "EC2", "S3", "Lambda", "Secrets", "RDS", "DynamoDB",
    "AccessAnalyzer", "CloudTrail"
]


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
        self._scan_id: str | None = None
        self._scan_status: str = "IDLE"  # IDLE, SCANNING, SUCCESS, FAILED, PARTIAL
        self._scan_started_at: str | None = None
        self._scan_started_perf: float | None = None
        self._scan_elapsed_seconds: float = 0.0

        self._active_phase: str | None = None
        self._active_phase_started_at: str | None = None
        self._completed_phases: List[str] = []
        self._last_progress_at: str | None = None

        self._completed_collectors: int = 0
        self._total_collectors: int = len(ALL_COLLECTOR_NAMES)
        self._collector_status: Dict[str, str] = {name: "PENDING" for name in ALL_COLLECTOR_NAMES}

        self._resources_discovered: int = 0
        self._users_discovered: int = 0
        self._roles_discovered: int = 0
        self._groups_discovered: int = 0
        self._policies_discovered: int = 0

        self._last_completed_scan_at: str | None = None
        self._last_completed_scan_id: str | None = None
        self._last_successful_scan_at: str | None = None
        self._last_successful_scan_id: str | None = None
        self._last_published_scan_id: str | None = None
        self._last_published_at: str | None = None
        self._last_error: str | None = None
        self._last_result: dict | None = None
        self._service_status: Dict[str, str] = {}
        self._failed_regions: List[str] = []
        self._successful_regions: List[str] = []
        self._scan_mode: str = "global"
        self._resolved_regions: List[str] = []
        self._phase_durations: Dict[str, Any] = {
            "discovery": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "iam_analysis": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "graph_construction": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "path_analysis": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "cloudtrail_correlation": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "finding_synthesis": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "publishing": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "total": {"duration_seconds": 0.0, "status": "SKIPPED"}
        }
        self._init_from_disk()

    def _init_from_disk(self):
        """Restore last successful scan metadata from durable disk storage and cache."""
        if os.path.exists(LAST_SCAN_FILE):
            try:
                with open(LAST_SCAN_FILE, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                if data:
                    self._last_result = data
                    self._last_completed_scan_at = (
                        data.get("last_completed_scan_at")
                        or data.get("lastCompletedScanAt")
                        or data.get("timestamp")
                    )
                    self._last_completed_scan_id = (
                        data.get("last_completed_scan_id")
                        or data.get("lastCompletedScanId")
                        or data.get("scan_id")
                        or data.get("scanId")
                    )
                    self._last_successful_scan_at = (
                        data.get("last_successful_scan_at")
                        or data.get("lastSuccessfulScanAt")
                    )
                    self._last_successful_scan_id = (
                        data.get("last_successful_scan_id")
                        or data.get("lastSuccessfulScanId")
                    )
                    self._last_published_scan_id = (
                        data.get("last_published_scan_id")
                        or data.get("lastPublishedScanId")
                        or data.get("snapshot_id")
                        or self._last_successful_scan_id
                        or self._last_completed_scan_id
                    )
                    self._last_published_at = (
                        data.get("last_published_at")
                        or data.get("lastPublishedAt")
                        or data.get("snapshot_published_at")
                        or self._last_successful_scan_at
                        or self._last_completed_scan_at
                    )
                    self._scan_mode = data.get("scan_mode") or data.get("scanMode") or "global"
                    self._resolved_regions = data.get("resolved_regions") or data.get("resolvedRegions") or []
                    if "phase_durations" in data:
                        self._phase_durations = data["phase_durations"]
                    if "durationSeconds" in data:
                        self._scan_elapsed_seconds = float(data["durationSeconds"])
            except Exception as e:
                logger.warning(f"Failed to restore scan metadata from disk: {e}")

        # Fallback check in cache if disk metadata was missing
        if not self._last_published_scan_id:
            try:
                cached_meta = cache.get("v1:scan_metadata")
                if cached_meta:
                    self._last_published_scan_id = cached_meta.get("snapshot_id") or cached_meta.get("scanId")
                    self._last_published_at = cached_meta.get("snapshot_published_at") or cached_meta.get("scanTimestamp")
                    self._last_completed_scan_at = self._last_completed_scan_at or cached_meta.get("lastCompletedScanAt")
                    self._last_completed_scan_id = self._last_completed_scan_id or cached_meta.get("lastCompletedScanId")
                    self._last_successful_scan_at = self._last_successful_scan_at or cached_meta.get("lastSuccessfulScanAt")
                    self._last_successful_scan_id = self._last_successful_scan_id or cached_meta.get("lastSuccessfulScanId")
                    self._scan_mode = cached_meta.get("scanMode") or self._scan_mode
                    self._resolved_regions = cached_meta.get("resolvedRegions") or self._resolved_regions
                    if "durationSeconds" in cached_meta:
                        self._scan_elapsed_seconds = float(cached_meta["durationSeconds"])
            except Exception:
                pass

    @property
    def is_running(self) -> bool:
        return self._is_running

    def _set_active_phase(self, phase_name: str) -> None:
        """Atomically advance the active scan phase and update progress heartbeat."""
        now_str = datetime.utcnow().isoformat() + "Z"
        self._active_phase = phase_name.upper()
        self._active_phase_started_at = now_str
        self._last_progress_at = now_str

    def _complete_phase(self, phase_name: str, duration_seconds: float, status: str = "COMPLETED") -> None:
        """Atomically record completed phase duration and update progress heartbeat."""
        now_str = datetime.utcnow().isoformat() + "Z"
        norm_name = phase_name.upper()
        self._phase_durations[norm_name] = {
            "duration_seconds": max(0.0, round(duration_seconds, 3)),
            "status": status
        }
        self._phase_durations[phase_name.lower()] = self._phase_durations[norm_name]
        if norm_name not in self._completed_phases and status == "COMPLETED":
            self._completed_phases.append(norm_name)
        if phase_name.lower() not in self._completed_phases and status == "COMPLETED":
            self._completed_phases.append(phase_name.lower())
        self._last_progress_at = now_str

    def get_status(self) -> dict:
        """Return current scan status for the frontend to poll.

        FAST IN-MEMORY READ:
        Must NOT call AWS DescribeRegions, start a scan, call Neo4j,
        or perform heavy computation. Reads strictly in-memory state.
        """
        if self._is_running and self._scan_started_perf is not None:
            elapsed = max(0.0, round(time.perf_counter() - self._scan_started_perf, 2))
        else:
            elapsed = self._scan_elapsed_seconds

        sched_info = {}
        try:
            from app.utils.scheduler import get_scheduler_status
            sched_info = get_scheduler_status()
        except Exception:
            pass

        current_snapshot = (
            self._last_published_scan_id
            or self._last_successful_scan_id
            or self._last_completed_scan_id
        )

        active_phase = self._active_phase
        if not self._is_running and not active_phase:
            if self._scan_status in ("COMPLETED", "PARTIAL", "SUCCESS"):
                active_phase = "COMPLETED"
            elif self._scan_status == "FAILED":
                active_phase = "FAILED"

        return {
            "is_scanning": self._is_running,
            "scan_id": self._scan_id,
            "scan_status": self._scan_status,
            "current_snapshot_id": current_snapshot,
            "new_scan_id": self._scan_id if self._is_running else None,
            "snapshot_id": current_snapshot,
            "snapshot_published_at": self._last_published_at,
            "started_at": self._scan_started_at,
            "elapsed_seconds": elapsed,
            "active_phase": active_phase,
            "active_phase_started_at": self._active_phase_started_at,
            "completed_phases": list(self._completed_phases),
            "phase_durations": self._phase_durations,
            "completed_collectors": self._completed_collectors,
            "total_collectors": self._total_collectors,
            "collector_status": dict(self._collector_status),
            "resources_discovered": self._resources_discovered,
            "users_discovered": self._users_discovered,
            "roles_discovered": self._roles_discovered,
            "groups_discovered": self._groups_discovered,
            "policies_discovered": self._policies_discovered,
            "last_completed_scan_at": self._last_completed_scan_at,
            "last_completed_scan_id": self._last_completed_scan_id,
            "last_successful_scan_at": self._last_successful_scan_at,
            "last_successful_scan_id": self._last_successful_scan_id,
            "last_published_scan_id": self._last_published_scan_id,
            "last_published_at": self._last_published_at,
            "failed_regions": list(self._failed_regions),
            "successful_regions": list(self._successful_regions),
            "last_error": self._last_error,
            "last_progress_at": self._last_progress_at,
            "scan_mode": self._scan_mode,
            "resolved_regions": list(self._resolved_regions),
            "scheduled_scan_interval_minutes": sched_info.get("scheduled_scan_interval_minutes"),
            "next_scheduled_scan_at": sched_info.get("next_scheduled_scan_at"),
            "last_result": self._last_result,
            "service_status": self._service_status,
        }

    def trigger_async_scan(self) -> dict:
        """Start a scan in a background thread with atomic slot claim. Returns immediately."""
        with self._lock:
            if self._is_running:
                return {
                    "status": "ALREADY_RUNNING",
                    "scan_id": self._scan_id,
                    "message": "A scan is already running"
                }
            self._is_running = True
            self._scan_id = str(uuid.uuid4())
            self._scan_status = "SCANNING"
            now_iso = datetime.utcnow().isoformat() + "Z"
            self._scan_started_at = now_iso
            self._scan_started_perf = time.perf_counter()
            self._scan_elapsed_seconds = 0.0
            self._last_progress_at = now_iso
            self._active_phase = "INITIALIZING"
            self._active_phase_started_at = now_iso
            self._completed_phases = []
            self._completed_collectors = 0
            self._total_collectors = len(ALL_COLLECTOR_NAMES)
            self._collector_status = {name: "PENDING" for name in ALL_COLLECTOR_NAMES}
            self._resources_discovered = 0
            self._users_discovered = 0
            self._roles_discovered = 0
            self._groups_discovered = 0
            self._policies_discovered = 0
            self._last_error = None
            scan_id = self._scan_id

        thread = threading.Thread(target=self._execute_scan, args=(scan_id,), daemon=True)
        thread.start()
        return {
            "status": "STARTED",
            "scan_id": scan_id,
            "message": "Scan started"
        }

    def run_scan(self) -> dict:
        """Execute a scan synchronously with atomic slot claim."""
        with self._lock:
            if self._is_running:
                logger.warning("Scan lock held. Skipping duplicate scheduled scan.")
                return {
                    "status": "ALREADY_RUNNING",
                    "scan_id": self._scan_id,
                    "message": "A scan is already running"
                }
            self._is_running = True
            self._scan_id = str(uuid.uuid4())
            self._scan_status = "SCANNING"
            now_iso = datetime.utcnow().isoformat() + "Z"
            self._scan_started_at = now_iso
            self._scan_started_perf = time.perf_counter()
            self._scan_elapsed_seconds = 0.0
            self._last_progress_at = now_iso
            self._active_phase = "INITIALIZING"
            self._active_phase_started_at = now_iso
            self._completed_phases = []
            self._completed_collectors = 0
            self._total_collectors = len(ALL_COLLECTOR_NAMES)
            self._collector_status = {name: "PENDING" for name in ALL_COLLECTOR_NAMES}
            self._resources_discovered = 0
            self._users_discovered = 0
            self._roles_discovered = 0
            self._groups_discovered = 0
            self._policies_discovered = 0
            self._last_error = None
            scan_id = self._scan_id

        return self._execute_scan(scan_id)

    def _execute_scan(self, scan_id: str) -> dict:
        self._last_error = None
        start_perf = time.perf_counter()
        self._scan_started_perf = start_perf
        self._service_status = {}

        self._phase_durations = {
            "discovery": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "iam_analysis": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "graph_construction": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "path_analysis": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "cloudtrail_correlation": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "finding_synthesis": {"duration_seconds": 0.0, "status": "SKIPPED"},
            "total": {"duration_seconds": 0.0, "status": "SKIPPED"}
        }

        logger.info(f"[INFO] SCAN START: Initializing AWS security scan (scan_id={scan_id})")

        try:
            # 0. AWS STS Authentication Check
            aws_diag = get_aws_diagnostic_info()
            if not aws_diag["authenticated"]:
                err_msg = f"AWS Authentication failed: {aws_diag.get('error')}"
                logger.error(f"[ERROR] {err_msg}")
                self._scan_status = "FAILED"
                self._last_error = err_msg
                duration = max(0.0, round(time.perf_counter() - start_perf, 3))
                self._scan_elapsed_seconds = duration
                self._phase_durations["total"] = {"duration_seconds": duration, "status": "FAILED"}
                self._last_result = {
                    "status": "failed",
                    "scan_id": scan_id,
                    "scan_status": "FAILED",
                    "error": err_msg,
                    "timestamp": self._scan_started_at,
                    "service_status": self._service_status,
                    "phase_durations": self._phase_durations,
                    "last_completed_scan_at": self._last_completed_scan_at,
                    "last_completed_scan_id": self._last_completed_scan_id,
                    "last_successful_scan_at": self._last_successful_scan_at,
                    "last_successful_scan_id": self._last_successful_scan_id,
                    "last_published_scan_id": self._last_published_scan_id,
                    "last_published_at": self._last_published_at,
                }
                return self._last_result

            logger.info(
                f"[INFO] AWS AUTHENTICATION: Account={aws_diag.get('account_id', 'unknown')}, "
                f"ARN={aws_diag.get('arn', 'unknown')}, Region={aws_diag.get('region', 'unknown')}"
            )

            # Cache previous inventory for regional resource preservation across partial scans
            prev_ec2 = list(self.inventory.ec2) if self.inventory.ec2 else (cache.get("v1:inventory:ec2") or [])
            prev_lambdas = list(self.inventory.lambdas) if self.inventory.lambdas else (cache.get("v1:inventory:lambda") or [])

            # Preserve current snapshot during scan execution; inventory is replaced atomically upon validation
            clear_region_cache()
            from app.services.aws.region_cache import get_resolved_scan_mode
            scanned_regions = list(get_all_regions())
            resolved_scan_mode = get_resolved_scan_mode()
            logger.info(f"[INFO] Scan mode: {resolved_scan_mode}, regions: {scanned_regions}")

            collector_funcs = {
                "IAM_Users": iam_service.collect_users,
                "IAM_Groups": iam_service.collect_groups,
                "IAM_Roles": iam_service.collect_roles,
                "IAM_Policies": iam_service.collect_policies,
                "EC2": ec2_service.collect_ec2_instances,
                "S3": s3_service.collect_s3_buckets,
                "Lambda": lambda_service.collect_lambda_functions,
                "Secrets": secrets_service.collect_secrets,
                "RDS": rds_service.collect_rds_instances,
                "DynamoDB": dynamodb_service.collect_dynamodb_tables,
                "AccessAnalyzer": access_analyzer_service.collect_access_analyzer_findings,
                "CloudTrail": cloudtrail_service.collect_recent_alerts,
            }

            collector_results: Dict[str, list] = {}
            collector_failures: Dict[str, str] = {}

            # 1. AWS API Data Collection (Concurrently)
            self._set_active_phase("discovery")
            phase_t0 = time.perf_counter()
            for c_name in ALL_COLLECTOR_NAMES:
                self._collector_status[c_name] = "RUNNING"

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(func): name
                    for name, func in collector_funcs.items()
                }
                scan_failed_regions: set = set()
                successful_regions_set: set = set()

                for future in concurrent.futures.as_completed(futures):
                    name = futures[future]
                    try:
                        res = future.result()
                        if hasattr(res, 'items') and hasattr(res, 'regional_status'):
                            # Typed RegionalCollectionResult
                            collector_results[name] = list(res.items)
                            for r_name, r_st in res.regional_status.items():
                                self._service_status[f"{name}:{r_name}"] = r_st
                            if getattr(res, 'successful_regions', None):
                                successful_regions_set.update(res.successful_regions)
                            if getattr(res, 'failed_regions', None):
                                scan_failed_regions.update(res.failed_regions)
                                # PRESERVATION GATE: Failed regions must NOT have their resources purged
                                if name == "EC2":
                                    existing_ids = {x.get("id") or x.get("instance_id") for x in collector_results[name]}
                                    for f_reg in res.failed_regions:
                                        preserved = [
                                            x for x in prev_ec2
                                            if x.get("region") == f_reg and (x.get("id") or x.get("instance_id")) not in existing_ids
                                        ]
                                        if not preserved:
                                            cached_res = cache.get("v1:resources") or []
                                            preserved = [
                                                x for x in cached_res
                                                if x.get("type") == "EC2" and x.get("region") == f_reg and (x.get("id") or x.get("name")) not in existing_ids
                                            ]
                                        if preserved:
                                            logger.info(f"[PRESERVED] Retained {len(preserved)} previous EC2 items from failed region {f_reg}")
                                            collector_results[name].extend(preserved)
                                            existing_ids.update(x.get("id") or x.get("instance_id") for x in preserved)
                                elif name == "Lambda":
                                    existing_names = {x.get("name") or x.get("function_name") for x in collector_results[name]}
                                    for f_reg in res.failed_regions:
                                        preserved = [
                                            x for x in prev_lambdas
                                            if x.get("region") == f_reg and (x.get("name") or x.get("function_name")) not in existing_names
                                        ]
                                        if not preserved:
                                            cached_res = cache.get("v1:resources") or []
                                            preserved = [
                                                x for x in cached_res
                                                if x.get("type") == "Lambda" and x.get("region") == f_reg and (x.get("name") or x.get("id")) not in existing_names
                                            ]
                                        if preserved:
                                            logger.info(f"[PRESERVED] Retained {len(preserved)} previous Lambda items from failed region {f_reg}")
                                            collector_results[name].extend(preserved)
                                            existing_names.update(x.get("name") or x.get("function_name") for x in preserved)

                            if len(res.items) > 0:
                                self._collector_status[name] = "SUCCESS_WITH_DATA"
                                self._service_status[name] = "SUCCESS_WITH_DATA"
                            elif getattr(res, 'failed_regions', None) and not getattr(res, 'successful_regions', None):
                                self._collector_status[name] = "FAILED"
                                self._service_status[name] = "FAILED"
                            else:
                                self._collector_status[name] = "SUCCESS_EMPTY"
                                self._service_status[name] = "SUCCESS_EMPTY"
                        else:
                            collector_results[name] = res
                            if res and len(res) > 0:
                                self._collector_status[name] = "SUCCESS_WITH_DATA"
                                self._service_status[name] = "SUCCESS_WITH_DATA"
                            else:
                                self._collector_status[name] = "SUCCESS_EMPTY"
                                self._service_status[name] = "SUCCESS_EMPTY"
                    except Exception as err:
                        logger.error(f"[ERROR] Collector {name} failed: {err}")
                        self._collector_status[name] = "FAILED"
                        self._service_status[name] = f"FAILED: {err}"
                        collector_failures[name] = str(err)
                        collector_results[name] = []

                    self._completed_collectors += 1
                    self._last_progress_at = datetime.utcnow().isoformat() + "Z"

                    # Live resource & identity count telemetry
                    items_len = len(collector_results.get(name, []))
                    if name == "IAM_Users":
                        self._users_discovered = items_len
                    elif name == "IAM_Roles":
                        self._roles_discovered = items_len
                    elif name == "IAM_Groups":
                        self._groups_discovered = items_len
                    elif name == "IAM_Policies":
                        self._policies_discovered = items_len
                    self._resources_discovered = sum(
                        len(collector_results.get(c, []))
                        for c in ["EC2", "S3", "Lambda", "Secrets", "RDS", "DynamoDB"]
                    )

            self._failed_regions = sorted(list(scan_failed_regions))
            reconcilable_regions = sorted(list(successful_regions_set - scan_failed_regions))
            self._successful_regions = reconcilable_regions

            # 1b. CRITICAL FAILURE GATE: Collector failure must NEVER look like empty AWS state
            failed_critical = [c for c in CRITICAL_COLLECTORS if c in collector_failures]
            if failed_critical:
                err_msg = f"Critical collector(s) failed: {', '.join(failed_critical)}"
                logger.error(f"[ERROR] Scan {scan_id} aborted: {err_msg}")
                self._scan_status = "FAILED"
                self._last_error = err_msg
                dur_disc = max(0.0, round(time.perf_counter() - phase_t0, 3))
                self._complete_phase("discovery", dur_disc, status="FAILED")
                duration = max(0.0, round(time.perf_counter() - start_perf, 3))
                self._scan_elapsed_seconds = duration
                self._phase_durations["total"] = {
                    "duration_seconds": duration,
                    "status": "FAILED"
                }
                self._last_result = {
                    "status": "failed",
                    "scan_id": scan_id,
                    "scan_status": "FAILED",
                    "error": err_msg,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "service_status": self._service_status,
                    "failed_regions": self._failed_regions,
                    "phase_durations": self._phase_durations,
                    "last_completed_scan_at": self._last_completed_scan_at,
                    "last_completed_scan_id": self._last_completed_scan_id,
                    "last_successful_scan_at": self._last_successful_scan_at,
                    "last_successful_scan_id": self._last_successful_scan_id,
                    "last_published_scan_id": self._last_published_scan_id,
                    "last_published_at": self._last_published_at,
                }
                # Do NOT prune Neo4j, do NOT publish empty cache, preserve previous snapshot
                return self._last_result

            # Assign working inventory (separate from published self.inventory)
            working_inventory = AWSInventory()
            working_inventory.users = collector_results.get("IAM_Users", [])
            working_inventory.groups = collector_results.get("IAM_Groups", [])
            working_inventory.roles = collector_results.get("IAM_Roles", [])
            working_inventory.policies = collector_results.get("IAM_Policies", [])
            working_inventory.ec2 = collector_results.get("EC2", [])
            working_inventory.s3 = collector_results.get("S3", [])
            working_inventory.lambdas = collector_results.get("Lambda", [])
            working_inventory.secrets = collector_results.get("Secrets", [])
            working_inventory.rds = collector_results.get("RDS", [])
            working_inventory.dynamodb = collector_results.get("DynamoDB", [])
            working_inventory.findings = collector_results.get("AccessAnalyzer", [])
            working_inventory.alerts = collector_results.get("CloudTrail", [])

            discovery_duration = max(0.0, round(time.perf_counter() - phase_t0, 3))
            self._complete_phase("discovery", discovery_duration, status="COMPLETED")

            logger.info(
                f"[INFO] Discovered AWS Resources: Users={len(working_inventory.users)}, "
                f"Roles={len(working_inventory.roles)}, Groups={len(working_inventory.groups)}, "
                f"Policies={len(working_inventory.policies)}, S3={len(working_inventory.s3)}, "
                f"EC2={len(working_inventory.ec2)}, Lambda={len(working_inventory.lambdas)}, "
                f"RDS={len(working_inventory.rds)}, DynamoDB={len(working_inventory.dynamodb)}, "
                f"Secrets={len(working_inventory.secrets)}"
            )

            # 2. Build Policy Document Map (Customer-Managed + Inline + Attached AWS-Managed)
            self._set_active_phase("iam_analysis")
            phase_t0 = time.perf_counter()
            policy_doc_map = {
                p['name']: p['document']
                for p in working_inventory.policies
            }

            # Inline policy documents
            for u in working_inventory.users:
                for in_name, in_doc in u.get('inlinePolicyDocuments', {}).items():
                    policy_doc_map[in_name] = in_doc
                    working_inventory.policies.append({
                        "name": in_name,
                        "arn": f"arn:aws:iam:inline:{u['name']}:{in_name}",
                        "type": "inline",
                        "document": in_doc,
                        "riskScore": 0
                    })
            for r in working_inventory.roles:
                for in_name, in_doc in r.get('inlinePolicyDocuments', {}).items():
                    policy_doc_map[in_name] = in_doc
                    working_inventory.policies.append({
                        "name": in_name,
                        "arn": f"arn:aws:iam:inline:{r['name']}:{in_name}",
                        "type": "inline",
                        "document": in_doc,
                        "riskScore": 0
                    })
            for g in working_inventory.groups:
                for in_name, in_doc in g.get('inlinePolicyDocuments', {}).items():
                    policy_doc_map[in_name] = in_doc
                    working_inventory.policies.append({
                        "name": in_name,
                        "arn": f"arn:aws:iam:inline:{g['name']}:{in_name}",
                        "type": "inline",
                        "document": in_doc,
                        "riskScore": 0
                    })

            # 2b. Fetch AWS-managed policy documents for attached policies + Permissions Boundaries
            aws_managed_arns: set = set()
            boundary_arns: set = set()

            for u in working_inventory.users:
                aws_managed_arns.update(
                    arn for arn in u.get('attachedPolicyArns', {}).values()
                    if '::aws:policy/' in arn
                )
                if u.get('permissionsBoundary'):
                    boundary_arns.add(u['permissionsBoundary'])

            for r in working_inventory.roles:
                aws_managed_arns.update(
                    arn for arn in r.get('attachedPolicyArns', {}).values()
                    if '::aws:policy/' in arn
                )
                if r.get('permissionsBoundary'):
                    boundary_arns.add(r['permissionsBoundary'])

            for g in working_inventory.groups:
                aws_managed_arns.update(
                    arn for arn in g.get('attachedPolicyArns', {}).values()
                    if '::aws:policy/' in arn
                )

            if aws_managed_arns:
                logger.info(f"[INFO] Resolving {len(aws_managed_arns)} attached AWS-managed policy documents")
                managed_docs = iam_service.fetch_managed_policy_documents(aws_managed_arns)
                policy_doc_map.update(managed_docs)
                for pol_name, doc_str in managed_docs.items():
                    if not any(p['name'] == pol_name for p in working_inventory.policies):
                        working_inventory.policies.append({
                            "name": pol_name,
                            "arn": f"arn:aws:iam::aws:policy/{pol_name}",
                            "type": "aws-managed",
                            "document": doc_str,
                            "riskScore": 0
                        })

            # Resolve permissions boundary documents before any authorization or risk evaluation
            if boundary_arns:
                logger.info(f"[INFO] Resolving {len(boundary_arns)} referenced permissions boundary policy documents")
                for barn in boundary_arns:
                    b_doc_obj = iam_service.fetch_policy_document_by_arn(barn)
                    if b_doc_obj:
                        b_name = b_doc_obj["name"]
                        b_doc_str = b_doc_obj["document"]
                        policy_doc_map[barn] = b_doc_str
                        policy_doc_map[b_name] = b_doc_str
                        if not any(p['name'] == b_name for p in working_inventory.policies):
                            working_inventory.policies.append({
                                "name": b_name,
                                "arn": barn,
                                "type": b_doc_obj.get("type", "boundary"),
                                "document": b_doc_str,
                                "riskScore": 0
                            })
                    else:
                        logger.warning(f"Could not resolve permissions boundary document for ARN: {barn}")

            # 3. Calculate Deterministic Risk Assessments & Scores
            for u in working_inventory.users:
                eval_res = risk_engine.get_user_risk_assessment(u, policy_doc_map)
                u['riskScore'] = eval_res['score']
                u['riskAssessment'] = eval_res

            for r in working_inventory.roles:
                eval_res = risk_engine.get_role_risk_assessment(r, policy_doc_map)
                r['riskScore'] = eval_res['score']
                r['riskAssessment'] = eval_res

            for s in working_inventory.s3:
                eval_res = risk_engine.get_resource_risk_assessment(s)
                s['riskScore'] = eval_res['score']
                s['riskAssessment'] = eval_res

            for e in working_inventory.ec2:
                eval_res = risk_engine.get_resource_risk_assessment(e)
                e['riskScore'] = eval_res['score']
                e['riskAssessment'] = eval_res

            for sec in working_inventory.secrets:
                eval_res = risk_engine.get_resource_risk_assessment(sec)
                sec['riskScore'] = eval_res['score']
                sec['riskAssessment'] = eval_res

            for rds in working_inventory.rds:
                eval_res = risk_engine.get_resource_risk_assessment(rds)
                rds['riskScore'] = eval_res['score']
                rds['riskAssessment'] = eval_res

            for ddb in working_inventory.dynamodb:
                eval_res = risk_engine.get_resource_risk_assessment(ddb)
                ddb['riskScore'] = eval_res['score']
                ddb['riskAssessment'] = eval_res

            # Update policies discovered count
            self._policies_discovered = len(working_inventory.policies)

            iam_analysis_duration = max(0.0, round(time.perf_counter() - phase_t0, 3))
            self._complete_phase("iam_analysis", iam_analysis_duration, status="COMPLETED")
            logger.info(f"[PERF] Phase 2 (IAM Analysis & Scoring) completed in {iam_analysis_duration}s")

            # 4. STEP 1 OF PIPELINE: Neo4j Configuration Sync (Idempotent MERGE, preserves ActivityEvent)
            self._set_active_phase("graph_construction")
            phase_t0 = time.perf_counter()
            neo4j_success = False
            try:
                graph_builder.build_graph_in_neo4j(
                    working_inventory,
                    successful_regions=reconcilable_regions if reconcilable_regions else None
                )
                neo4j_success = True
            except Exception as db_err:
                logger.warning(f"Neo4j database sync skipped/failed: {db_err}")

            # 5. STEP 2 OF PIPELINE: Load Base NetworkX Graph
            try:
                if neo4j_success:
                    G = graph_loader.load_graph_from_neo4j()
                    if G.number_of_nodes() == 0:
                        G = graph_loader.build_local_graph(working_inventory)
                else:
                    G = graph_loader.build_local_graph(working_inventory)
            except Exception as loader_err:
                logger.warning(f"Neo4j loader exception: {loader_err}. Building local NetworkX model.")
                G = graph_loader.build_local_graph(working_inventory)

            graph_construction_duration = max(0.0, round(time.perf_counter() - phase_t0, 3))
            self._complete_phase("graph_construction", graph_construction_duration, status="COMPLETED")
            logger.info(f"[PERF] Phase 3 (Graph Construction) completed in {graph_construction_duration}s")

            # 6. STEP 3 OF PIPELINE: Attack Path Engine Analysis on Graph
            self._set_active_phase("path_analysis")
            phase_t0 = time.perf_counter()
            _policy_doc_map = {
                p.get('name', ''): p.get('document', '{}')
                for p in working_inventory.policies if p.get('name')
            }
            _policy_doc_map.update({
                p.get('arn', ''): p.get('document', '{}')
                for p in working_inventory.policies if p.get('arn')
            })
            attack_paths = path_engine.find_attack_paths(
                G,
                inventory=working_inventory,
                policy_doc_map=_policy_doc_map,
            )
            path_analysis_duration = max(0.0, round(time.perf_counter() - phase_t0, 3))
            self._complete_phase("path_analysis", path_analysis_duration, status="COMPLETED")
            logger.info(f"[PERF] Phase 4 (Path Analysis) completed in {path_analysis_duration}s: {len(attack_paths)} paths detected")

            # 7. STEP 4 OF PIPELINE: CloudTrail Activity Normalization & Correlation with Graph/Paths
            self._set_active_phase("cloudtrail_correlation")
            phase_t0 = time.perf_counter()
            correlation_result = cloudtrail_correlator.correlate_activity_with_graph(
                working_inventory.alerts,
                working_inventory,
                G,
                attack_paths=attack_paths
            )
            correlated_findings = correlation_result.get("correlated_findings", [])
            activity_metrics = correlation_result.get("metrics", {})
            cloudtrail_correlation_duration = max(0.0, round(time.perf_counter() - phase_t0, 3))
            self._complete_phase("cloudtrail_correlation", cloudtrail_correlation_duration, status="COMPLETED")

            nodes_count = G.number_of_nodes()
            edges_count = G.number_of_edges()
            logger.info(
                f"[PERF] Phase 5 (CloudTrail Correlation) completed in {cloudtrail_correlation_duration}s: "
                f"{nodes_count} nodes, {edges_count} edges, {len(correlated_findings)} correlated findings"
            )

            # 8. STEP 5 OF PIPELINE: Findings & Severity Groupings
            self._set_active_phase("FINDING_SYNTHESIS")
            phase_t0 = time.perf_counter()
            all_scored_items = (
                working_inventory.users + working_inventory.roles +
                working_inventory.s3 + working_inventory.ec2 +
                working_inventory.secrets + working_inventory.rds +
                working_inventory.dynamodb
            )

            critical_items = [x for x in all_scored_items if x.get('riskScore', 0) >= 80]
            high_items = [x for x in all_scored_items if 60 <= x.get('riskScore', 0) < 80]
            medium_items = [x for x in all_scored_items if 40 <= x.get('riskScore', 0) < 60]
            low_items = [x for x in all_scored_items if 0 < x.get('riskScore', 0) < 40]

            total_findings_count = len(critical_items) + len(high_items) + len(medium_items) + len(low_items)

            # Calculate Global 5-Category Posture Score
            global_posture = risk_engine.compute_global_security_score(
                working_inventory,
                attack_paths,
                working_inventory.alerts
            )
            security_score = global_posture["overall_score"]
            recommendations = _generate_recommendations(working_inventory, attack_paths)

            from app.services.aws.ec2_service import is_running_ec2
            running_ec2 = [e for e in working_inventory.ec2 if is_running_ec2(e)]

            # 9. Record ScanHistory (Accurate Severity Metrics)
            scan_timestamp = datetime.utcnow().isoformat() + "Z"
            resources_count = (
                len(running_ec2) + len(working_inventory.s3) +
                len(working_inventory.lambdas) + len(working_inventory.secrets) +
                len(working_inventory.rds) + len(working_inventory.dynamodb)
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
                        "dur": max(0.0, round(time.perf_counter() - start_perf, 2)),
                        "res": resources_count,
                        "total_findings": total_findings_count,
                        "crit": len(critical_items),
                        "high": len(high_items),
                        "med": len(medium_items),
                        "low": len(low_items),
                        "paths": len(attack_paths),
                        "ct_events": len(working_inventory.alerts),
                        "corr": len(correlated_findings),
                        "score": security_score,
                        "nodes": nodes_count,
                        "edges": edges_count
                    }
                )
            except Exception as hist_err:
                logger.debug(f"Neo4j ScanHistory creation skipped: {hist_err}")

            finding_synthesis_duration = max(0.0, round(time.perf_counter() - phase_t0, 3))
            self._complete_phase("FINDING_SYNTHESIS", finding_synthesis_duration, status="COMPLETED")
            self._set_active_phase("PUBLISHING")
            phase_t0 = time.perf_counter()

            # 10. STEP 6 OF PIPELINE: Build Atomic Snapshot in Memory & Publish Gate
            attack_path_node_ids = set()
            for p in attack_paths:
                for n in p.get("nodes", []):
                    attack_path_node_ids.add(n.get("id"))

            relevant_node_ids = set()
            for nid, attr in G.nodes(data=True):
                ntype = attr.get('type', 'Resource')
                if ntype in ('User', 'Group', 'Role', 'Policy'):
                    relevant_node_ids.add(nid)
                elif G.in_degree(nid) > 0 or G.out_degree(nid) > 0 or nid in attack_path_node_ids:
                    relevant_node_ids.add(nid)

            canonical_emitted_node_ids = set()
            canonical_emitted_arns = set()
            nid_to_canonical = {}

            for nid, attr in G.nodes(data=True):
                canon = attr.get('canonical_id') or nid
                nid_to_canonical[nid] = canon

            cytoscape_elements = []
            role_map = {r['name']: r for r in working_inventory.roles}
            user_map = {u['name']: u for u in working_inventory.users}

            for nid in relevant_node_ids:
                attr = G.nodes[nid]
                if attr.get('is_canonical') is False:
                    continue

                canonical_id = attr.get('canonical_id') or nid
                arn = attr.get('arn', '')

                if canonical_id in canonical_emitted_node_ids:
                    continue
                if arn and arn in canonical_emitted_arns:
                    continue

                canonical_emitted_node_ids.add(canonical_id)
                if arn:
                    canonical_emitted_arns.add(arn)

                node_type = attr.get('type', 'Resource')
                label = attr.get('label', canonical_id)
                extra: dict = {}
                if node_type == 'Role':
                    role = role_map.get(label) or role_map.get(canonical_id)
                    if role:
                        extra['trustPolicy'] = role.get('trustPolicy', '')
                elif node_type == 'User':
                    user = user_map.get(label) or user_map.get(canonical_id)
                    if user:
                        extra['policies'] = user.get('policies', [])

                cytoscape_elements.append({
                    "data": {
                        "id": canonical_id,
                        "label": label,
                        "type": node_type,
                        "riskScore": attr.get('riskScore', 0),
                        "arn": arn,
                        "description": attr.get('description', ''),
                        **extra
                    }
                })

            seen_edges = set()
            for s, t, attr in G.edges(data=True):
                canon_s = nid_to_canonical.get(s, s)
                canon_t = nid_to_canonical.get(t, t)
                if canon_s in canonical_emitted_node_ids and canon_t in canonical_emitted_node_ids:
                    if canon_s == canon_t:
                        continue
                    lbl = attr.get('label', '')
                    act = attr.get('action', '')
                    edge_sig = f"{canon_s}->{canon_t}:{lbl}:{act}"
                    if edge_sig in seen_edges:
                        continue
                    seen_edges.add(edge_sig)

                    cytoscape_elements.append({
                        "data": {
                            "id": f"e-{canon_s}-{canon_t}-{len(seen_edges)}",
                            "source": canon_s,
                            "target": canon_t,
                            "label": lbl,
                            "isActivity": attr.get('is_activity', False),
                            "timestamp": attr.get('timestamp', ''),
                            "sourceIp": attr.get('sourceIp', ''),
                            "edge_type": attr.get('edge_type', attr.get('label', '')),
                            "provenance_source": attr.get('source', ''),
                            "principal": attr.get('principal', ''),
                            "principal_type": attr.get('principal_type', ''),
                            "policy_arn": attr.get('policy_arn', ''),
                            "policy_name": attr.get('policy_name', ''),
                            "statement_sid": attr.get('statement_sid', ''),
                            "effect": attr.get('effect', ''),
                            "action": attr.get('action', ''),
                            "resource": attr.get('resource', ''),
                            "resource_arn": attr.get('resource_arn', ''),
                            "condition_status": attr.get('condition_status', ''),
                            "decision": attr.get('decision', 'ALLOWED'),
                            "region": attr.get('region', ''),
                            "why": attr.get('why', ''),
                            "evidence": attr.get('evidence', {}),
                            "access_category": attr.get('access_category') or classify_action_category(attr.get('action', ''))
                        }
                    })

            # Critical Risks Findings list & Canonical Security Findings Reconciled
            self._set_active_phase("finding_synthesis")
            phase_t0 = time.perf_counter()
            canonical_findings = finding_service.reconcile_scan_findings(
                inventory=working_inventory,
                attack_paths=attack_paths,
                correlated_findings=correlated_findings,
                successful_regions=reconcilable_regions,
                failed_regions=self._failed_regions,
                scan_timestamp=scan_timestamp
            )
            finding_synthesis_duration = max(0.0, round(time.perf_counter() - phase_t0, 3))
            self._complete_phase("finding_synthesis", finding_synthesis_duration, status="COMPLETED")
            logger.info(f"[PERF] Phase 6 (Finding Synthesis & Lifecycle) completed in {finding_synthesis_duration}s: {len(canonical_findings)} total findings")

            duration = max(0.0, round(time.perf_counter() - start_perf, 3))
            self._phase_durations["total"] = {"duration_seconds": duration, "status": "COMPLETED"}
            self._scan_elapsed_seconds = duration
            phase_durations = self._phase_durations
            logger.info(
                f"[PERF] Scan {scan_id} Pipeline Timing: "
                f"discovery={discovery_duration}s, "
                f"iam_analysis={iam_analysis_duration}s, "
                f"graph_construction={graph_construction_duration}s, "
                f"path_analysis={path_analysis_duration}s, "
                f"cloudtrail_correlation={cloudtrail_correlation_duration}s, "
                f"finding_synthesis={finding_synthesis_duration}s | "
                f"total={duration}s"
            )

            critical_risks = [
                {
                    "id": f.id,
                    "identity": f.principal or f.resource or "unknown",
                    "identityType": f.principalType or f.resourceType or "Resource",
                    "issue": f.description or f.title,
                    "severity": f.severity,
                    "riskScore": f.riskScore,
                    "recommendation": f.remediation.title if f.remediation else "Review configuration"
                }
                for f in canonical_findings
                if f.status == "OPEN" and f.riskScore >= 40
            ]
            critical_risks.sort(key=lambda x: x['riskScore'], reverse=True)

            res_breakdown = [
                {"type": "IAM Users", "count": len(working_inventory.users)},
                {"type": "IAM Roles", "count": len(working_inventory.roles)},
                {"type": "IAM Policies", "count": len(working_inventory.policies)},
                {"type": "S3 Buckets", "count": len(working_inventory.s3)},
                {"type": "EC2 Instances", "count": len(running_ec2)},
                {"type": "Lambda Functions", "count": len(working_inventory.lambdas)},
                {"type": "Secrets", "count": len(working_inventory.secrets)},
                {"type": "RDS Databases", "count": len(working_inventory.rds)},
                {"type": "DynamoDB Tables", "count": len(working_inventory.dynamodb)}
            ]
            res_breakdown = [r for r in res_breakdown if r["count"] > 0]

            all_identities = working_inventory.users + working_inventory.roles
            sorted_identities = sorted(all_identities, key=lambda x: x.get('riskScore', 0), reverse=True)
            top_identities = [
                {
                    "name": x.get('name') or x.get('username', 'Unknown'),
                    "type": "User" if "mfaEnabled" in x else "Role",
                    "riskScore": x.get('riskScore', 0),
                    "arn": x.get('arn', '')
                }
                for x in sorted_identities[:5]
                if x.get('riskScore', 0) > 0
            ]

            critical_paths_list = [p for p in attack_paths if p.get('severity') in ['critical', 'high']][:5]

            final_scan_status = "PARTIAL" if scan_failed_regions else "SUCCESS"

            # Update scan completion / success metadata:
            # - SUCCESS: updates both last_completed and last_successful
            # - PARTIAL: updates last_completed, preserves existing last_successful
            self._last_completed_scan_at = scan_timestamp
            self._last_completed_scan_id = scan_id
            if final_scan_status == "SUCCESS":
                self._last_successful_scan_at = scan_timestamp
                self._last_successful_scan_id = scan_id

            open_canonical = [f for f in canonical_findings if f.status == "OPEN"]
            crit_canonical = [f for f in open_canonical if f.severity == "critical"]
            high_canonical = [f for f in open_canonical if f.severity == "high"]
            med_canonical = [f for f in open_canonical if f.severity == "medium"]
            low_canonical = [f for f in open_canonical if f.severity == "low"]

            dashboard_summary = {
                "securityScore": f"{security_score} / 100",
                "stats": {
                    "users": len(working_inventory.users),
                    "roles": len(working_inventory.roles),
                    "policies": len(working_inventory.policies),
                    "risks": len(open_canonical),
                    "paths": len(attack_paths),
                    "resources": resources_count
                },
                "activityMetrics": {
                    "staticAttackPaths": len(attack_paths),
                    "observedSecurityEvents": len(working_inventory.alerts),
                    "correlatedFindings": len(correlated_findings),
                    "observedAttackActivity": activity_metrics.get("observed_attack_activity_count", 0)
                },
                "riskDistribution": [
                    {"name": "Critical", "value": len(crit_canonical), "color": "#EF4444"},
                    {"name": "High", "value": len(high_canonical), "color": "#F59E0B"},
                    {"name": "Medium", "value": len(med_canonical), "color": "#3B82F6"},
                    {"name": "Low", "value": len(low_canonical), "color": "#10B981"}
                ],
                "recentAlerts": working_inventory.alerts[:5],
                "criticalPaths": critical_paths_list,
                "recommendations": [
                    {"title": r.get('title', 'Remediation'), "desc": r.get('desc', r.get('description', ''))}
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
                    "scanned_regions": scanned_regions,
                    "scan_mode": resolved_scan_mode,
                    "successful_regions": reconcilable_regions,
                    "failed_regions": self._failed_regions,
                    "phase_durations": phase_durations
                },
                "phaseDurations": phase_durations,
                "topRiskyIdentities": top_identities,
                "resourceBreakdown": res_breakdown,
                "scanId": scan_id,
                "scanStatus": final_scan_status,
                "scanMode": resolved_scan_mode,
                "scannedRegions": scanned_regions,
                "resolvedRegions": scanned_regions,
                "successfulRegions": reconcilable_regions,
                "lastCompletedScanAt": self._last_completed_scan_at,
                "lastCompletedScanId": self._last_completed_scan_id,
                "lastSuccessfulScanAt": self._last_successful_scan_at,
                "lastSuccessfulScanId": self._last_successful_scan_id,
                "lastPublishedScanId": scan_id,
                "lastPublishedAt": scan_timestamp,
                "snapshot_id": scan_id,
                "snapshot_published_at": scan_timestamp,
                "lastError": None,
                "serviceStatus": self._service_status,
                "failedRegions": self._failed_regions
            }

            scan_metadata = {
                "scanId": scan_id,
                "snapshot_id": scan_id,
                "scanTimestamp": scan_timestamp,
                "snapshot_published_at": scan_timestamp,
                "scanStatus": final_scan_status,
                "scanMode": resolved_scan_mode,
                "scannedRegions": scanned_regions,
                "resolvedRegions": scanned_regions,
                "successfulRegions": reconcilable_regions,
                "lastCompletedScanAt": self._last_completed_scan_at,
                "lastCompletedScanId": self._last_completed_scan_id,
                "lastSuccessfulScanAt": self._last_successful_scan_at,
                "lastSuccessfulScanId": self._last_successful_scan_id,
                "lastPublishedScanId": scan_id,
                "lastPublishedAt": scan_timestamp,
                "lastError": None,
                "serviceStatus": self._service_status,
                "failedRegions": self._failed_regions,
                "durationSeconds": duration,
                "resourcesFound": resources_count,
                "risksFound": total_findings_count,
                "phaseDurations": phase_durations
            }

            try:
                from app.services.simulation.effective_access import compute_effective_access
                all_res = (
                    working_inventory.s3 + working_inventory.secrets + working_inventory.rds +
                    working_inventory.dynamodb + running_ec2 + working_inventory.lambdas
                )
                effective_access_records = compute_effective_access(working_inventory, _policy_doc_map, all_res)
            except Exception as eff_err:
                logger.warning(f"Failed to compute effective access snapshot: {eff_err}")
                effective_access_records = []

            new_snapshot = {
                "v1:users": working_inventory.users,
                "v1:roles": working_inventory.roles,
                "v1:groups": working_inventory.groups,
                "v1:policies": working_inventory.policies,
                "v1:inventory:ec2": working_inventory.ec2,
                "v1:inventory:lambda": working_inventory.lambdas,
                "v1:resources": (
                    working_inventory.users + working_inventory.roles +
                    running_ec2 + working_inventory.s3 +
                    working_inventory.lambdas + working_inventory.secrets +
                    working_inventory.rds + working_inventory.dynamodb
                ),
                "v1:alerts": working_inventory.alerts,
                "v1:correlated_risks": correlated_findings,
                "v1:attack-paths": attack_paths,
                "v1:global_posture": global_posture,
                "v1:graph": cytoscape_elements,
                "v1:effective_access": effective_access_records,
                "v1:risks": critical_risks,
                "v1:findings": [f.model_dump() for f in canonical_findings],
                "v1:dashboard": dashboard_summary,
                "v1:scan_metadata": scan_metadata,
            }

            # Atomic publication under single lock: replaces previous cache atomically
            cache.set_many(new_snapshot)
            logger.info(f"[INFO] Authoritative scan snapshot published atomically (scan_id={scan_id}, status={final_scan_status})")

            publishing_duration = max(0.0, round(time.perf_counter() - phase_t0, 3))
            self._complete_phase("PUBLISHING", publishing_duration, status="COMPLETED")
            self._set_active_phase("COMPLETED")

            # Update authoritative in-memory state only upon publication
            self.inventory = working_inventory
            self._last_published_scan_id = scan_id
            self._last_published_at = scan_timestamp

            # Persist authoritative scan metadata to durable disk storage
            try:
                os.makedirs(os.path.dirname(LAST_SCAN_FILE), exist_ok=True)
                with open(LAST_SCAN_FILE, "w", encoding="utf-8") as fp:
                    json.dump(scan_metadata, fp, indent=2)
            except Exception as disk_err:
                logger.warning(f"Failed to persist scan metadata to disk: {disk_err}")

            self._scan_status = final_scan_status
            self._last_error = None

            self._last_result = {
                "status": "partial" if scan_failed_regions else "success",
                "scan_id": scan_id,
                "scan_status": final_scan_status,
                "scan_mode": resolved_scan_mode,
                "timestamp": scan_timestamp,
                "last_completed_scan_at": self._last_completed_scan_at,
                "last_completed_scan_id": self._last_completed_scan_id,
                "last_successful_scan_at": self._last_successful_scan_at,
                "last_successful_scan_id": self._last_successful_scan_id,
                "last_published_scan_id": self._last_published_scan_id,
                "last_published_at": self._last_published_at,
                "snapshot_id": scan_id,
                "snapshot_published_at": scan_timestamp,
                "duration_seconds": duration,
                "nodes_count": nodes_count,
                "edges_count": edges_count,
                "attack_paths_count": len(attack_paths),
                "security_score": security_score,
                "total_findings": total_findings_count,
                "critical_findings": len(critical_items),
                "service_status": self._service_status,
                "failed_regions": self._failed_regions,
                "successful_regions": reconcilable_regions,
                "scanned_regions": scanned_regions,
                "resolved_regions": scanned_regions,
                "phase_durations": self._phase_durations
            }

            return self._last_result

        except Exception as e:
            logger.error(f"[ERROR] Scan execution encountered an unexpected failure: {e}", exc_info=True)
            self._scan_status = "FAILED"
            self._last_error = str(e)
            if self._active_phase:
                dur = max(0.0, round(time.perf_counter() - phase_t0, 3)) if phase_t0 else 0.0
                self._complete_phase(self._active_phase, dur, status="FAILED")
            self._set_active_phase("FAILED")
            duration = max(0.0, round(time.perf_counter() - start_perf, 3))
            self._phase_durations["total"] = {"duration_seconds": duration, "status": "FAILED"}
            self._scan_elapsed_seconds = duration
            self._last_result = {
                "status": "failed",
                "scan_id": scan_id,
                "scan_status": "FAILED",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "service_status": self._service_status,
                "phase_durations": self._phase_durations,
                "last_completed_scan_at": self._last_completed_scan_at,
                "last_completed_scan_id": self._last_completed_scan_id,
                "last_successful_scan_at": self._last_successful_scan_at,
                "last_successful_scan_id": self._last_successful_scan_id,
                "last_published_scan_id": self._last_published_scan_id,
                "last_published_at": self._last_published_at,
            }
            return self._last_result
        finally:
            with self._lock:
                self._is_running = False
                if self._active_phase not in ("COMPLETED", "FAILED"):
                    if self._scan_status == "FAILED":
                        self._active_phase = "FAILED"
                    else:
                        self._active_phase = "COMPLETED"
                self._active_phase_started_at = None
                if self._scan_started_perf is not None:
                    self._scan_elapsed_seconds = max(0.0, round(time.perf_counter() - self._scan_started_perf, 2))


scan_manager = ScanManager()
