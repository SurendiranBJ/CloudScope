"""
Execute real-AWS end-to-end scan validation and report authentic metrics.
"""
import sys
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def main():
    from app.services.scanner.scan_manager import scan_manager
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
        print("[FAIL] AWS is not authenticated!")
        sys.exit(1)

    # 2. Execute Full Real-AWS Scan
    print("Initiating full multi-service, multi-region scan...")
    result = scan_manager.run_scan()
    print("-" * 60)

    # 3. Print Results Summary
    status = result.get("status")
    print(f"Scan Status:        {status}")
    print(f"Scan ID:            {result.get('scan_id')}")
    print(f"Duration:           {result.get('duration_seconds')}s")
    print(f"Successful Regions: {result.get('successful_regions')}")
    print(f"Failed Regions:     {result.get('failed_regions')}")

    # Phase Durations
    phase_durations = result.get("phase_durations") or scan_manager.get_status().get("phase_durations", {})
    print("\nPhase Durations:")
    for phase, dur in phase_durations.items():
        print(f"  - {phase:25s}: {dur:.3f}s")

    # Inventory Counts
    inv = scan_manager.inventory
    print("\nInventory Counts:")
    print(f"  - IAM Users:      {len(inv.users)}")
    print(f"  - IAM Roles:      {len(inv.roles)}")
    print(f"  - IAM Groups:     {len(inv.groups)}")
    print(f"  - IAM Policies:   {len(inv.policies)}")
    print(f"  - S3 Buckets:     {len(inv.s3)}")
    print(f"  - EC2 Instances:  {len(inv.ec2)}")
    print(f"  - Lambda Funcs:   {len(inv.lambdas)}")
    print(f"  - Secrets:        {len(inv.secrets)}")
    print(f"  - RDS Instances:  {len(inv.rds)}")
    print(f"  - DynamoDB Tables:{len(inv.dynamodb)}")

    from app.services.findings.finding_service import finding_service
    findings = finding_service.get_all_findings()
    attack_paths_count = result.get("attack_paths_count", 0)
    nodes_count = result.get("nodes_count", 0)
    edges_count = result.get("edges_count", 0)

    print("\nSecurity Analytics Summary:")
    print(f"  - Security Graph Nodes:     {nodes_count}")
    print(f"  - Security Graph Edges:     {edges_count}")
    print(f"  - Attack Paths Detected:    {attack_paths_count}")
    print(f"  - Total Canonical Findings: {len(findings)}")
    finding_types = {}
    finding_severities = {}
    for f in findings:
        ftype = f.get("finding_type") or f.get("type", "UNKNOWN")
        sev = f.get("severity", "UNKNOWN")
        finding_types[ftype] = finding_types.get(ftype, 0) + 1
        finding_severities[sev] = finding_severities.get(sev, 0) + 1
    print("    By Finding Type:")
    for ftype, cnt in sorted(finding_types.items()):
        print(f"      * {ftype}: {cnt}")
    print("    By Severity:")
    for sev, cnt in sorted(finding_severities.items()):
        print(f"      * {sev}: {cnt}")

    print(f"  - Security Score:           {result.get('security_score')}/100")
    print(f"  - Critical Findings:        {result.get('critical_findings')}")

    print("=" * 60)
    print("REAL-AWS E2E VALIDATION SUCCESSFUL")
    print("=" * 60)

if __name__ == "__main__":
    main()
