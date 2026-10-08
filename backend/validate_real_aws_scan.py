"""
Execute real-AWS end-to-end scan validation and report authentic metrics.
"""
import sys
import time
import logging
import os
from typing import Dict, Any

# Ensure we run in a test-friendly mode without breaking prod rules during validation script
os.environ["DEV_AUTH_MODE"] = "true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def main():
    from app.services.scanner.scan_coordinator import scan_coordinator
    from app.services.scanner.current_snapshot import (
        has_published_snapshot,
        get_current_snapshot_id,
        get_current_snapshot_published_at,
        get_current_findings,
        get_current_resources,
        get_current_users,
        get_current_roles,
        get_current_risks,
        get_current_graph,
    )
    from app.services.aws.session import get_aws_diagnostic_info

    print("=" * 60)
    print("CLOUDSCOPE PHASE 6: REAL-AWS END-TO-END SCAN VALIDATION")
    print("=" * 60)

    # 1. Verify STS Identity
    diag = get_aws_diagnostic_info()
    print(f"STS Authenticated: {diag.get('authenticated')}")
    print(f"AWS Account ID:   {diag.get('account_id')}")
    print(f"Caller Identity:  {diag.get('arn')}")
    print(f"Configured Region:{diag.get('region')}")
    print("-" * 60)

    if not diag.get("authenticated"):
        print("[BLOCKED] AWS is not authenticated. Ensure valid AWS credentials are provided.")
        sys.exit(1)

    # 2. Trigger Scan via canonical coordinator
    print("Initiating full multi-service, multi-region scan via coordinator...")
    trigger_resp = scan_coordinator.request_scan(trigger_type="MANUAL", created_by="validation-script")
    if trigger_resp.get("status") not in ["STARTED", "ALREADY_RUNNING"]:
        print(f"[FAIL] Scan failed to start: {trigger_resp}")
        sys.exit(1)

    print("Waiting for scan to reach a terminal state...")
    time.sleep(1) # Give worker thread time to initialize state
    timeout = 300  # 5 minutes bounded timeout
    start_time = time.time()
    
    status_data = {}
    while time.time() - start_time < timeout:
        status_data = scan_coordinator.get_status()
        is_scanning = status_data.get("is_scanning", False)
        if not is_scanning:
            print(f"Scan reached terminal state: {status_data.get('status')}")
            break
        time.sleep(5)
    else:
        print("[FAIL] Scan timed out after 5 minutes remaining in SCANNING state.")
        sys.exit(1)

    scan_id = trigger_resp.get("scan_id")
    
    # 3. Verify Durable Snapshot Publication
    if not has_published_snapshot():
        print(f"[FAIL] Scan did not succeed or snapshot was not published. Last state: {state}")
        sys.exit(1)

    snapshot_id = get_current_snapshot_id()
    if snapshot_id != scan_id:
        print(f"[FAIL] The published snapshot {snapshot_id} does not match our triggered scan {scan_id}.")
        sys.exit(1)
        
    pub_time = get_current_snapshot_published_at()
    print("-" * 60)
    print(f"Snapshot Published: YES")
    print(f"Snapshot ID:        {snapshot_id}")
    print(f"Published At:       {pub_time}")
    print(f"Duration:           {status_data.get('duration_seconds')}s")

    # 4. Authoritative Metrics Retrieval
    # Verify graph consistency
    graph_elements = get_current_graph() or []
    nodes_count = len([e for e in graph_elements if e.get("group") == "nodes"])
    edges_count = len([e for e in graph_elements if e.get("group") == "edges"])
    
    if edges_count > 0 and nodes_count == 0:
        print(f"[FAIL] Graph inconsistency: 0 nodes but {edges_count} edges.")
        sys.exit(1)

    resources = get_current_resources() or []
    users = get_current_users() or []
    roles = get_current_roles() or []
    findings = get_current_findings() or []
    risks = get_current_risks() or []

    print("\nInventory Counts:")
    print(f"  - Total Resources: {len(resources)}")
    print(f"  - Total Users:     {len(users)}")
    print(f"  - Total Roles:     {len(roles)}")
    
    print("\nSecurity Analytics Summary:")
    print(f"  - Security Graph Nodes:     {nodes_count}")
    print(f"  - Security Graph Edges:     {edges_count}")
    print(f"  - Total Canonical Findings: {len(findings)}")
    print(f"  - Risk Assessment Items:    {len(risks)}")
    
    if not findings and not resources:
        print("[FAIL] Snapshot is completely empty. Expected at least some resources or permission errors.")
        sys.exit(1)

    print("=" * 60)
    print("REAL-AWS E2E VALIDATION SUCCESSFUL")
    print("=" * 60)
    sys.exit(0)

if __name__ == "__main__":
    main()
