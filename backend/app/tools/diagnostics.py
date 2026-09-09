"""
CloudScope IAM Trust & Attack-Path Diagnostic CLI Tool.

Run via:
    python -m app.tools.diagnostics

Performs comprehensive diagnostic verification of the 4-layer IAM trust model:
1. Wildcard Trust without Assume Permission -> NO CAN_ASSUME edge.
2. Wildcard Trust with Assume Permission -> Definitive CAN_ASSUME edge.
3. Group-inherited Assume Permission -> Definitive CAN_ASSUME edge.
4. Explicit Deny Precedence (direct or group) -> NO CAN_ASSUME edge.
5. Trust Conditions with runtime keys (MFA, ExternalId, SourceIp) -> CONDITIONAL_TRUST metadata, NO CAN_ASSUME edge.
6. Blast Radius -> Only counts real cloud assets (S3, Secrets, RDS, DynamoDB, EC2, Lambda), never identities.
"""

import sys
import json
import networkx as nx
from typing import Dict, Any, List

from app.services.attack.policy_evaluator import (
    evaluate_assume_role_trust_with_evidence,
    principal_effective_allows_assume_role,
    evaluate_trust_statement_condition,
)
from app.services.attack.path_engine import (
    find_attack_paths,
    compute_effective_blast_radius,
)


def run_diagnostics():
    print("=" * 100)
    print(" CLOUDSCOPE AUTHORITATIVE IAM TRUST & ATTACK-PATH DIAGNOSTICS")
    print("=" * 100)

    total_checks = 0
    passed_checks = 0

    print(f"\n{'SOURCE':<25} | {'RELATIONSHIP':<14} | {'TARGET':<25} | {'STATUS':<12} | {'EVIDENCE'}")
    print("-" * 115)

    # ──────────────────────────────────────────────────────────────────────────
    # SCENARIO 1: Wildcard Trust + Unprivileged User vs Authorized User
    # ──────────────────────────────────────────────────────────────────────────
    wildcard_role = {
        "name": "OverlyTrustingAdminRole",
        "arn": "arn:aws:iam::123456789012:role/OverlyTrustingAdminRole",
        "trustPolicy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
        }
    }
    alice_unprivileged = {
        "name": "developer-alice",
        "arn": "arn:aws:iam::123456789012:user/developer-alice",
        "policies": ["S3ReadPolicy"],
        "attachedPolicies": []
    }
    bob_authorized = {
        "name": "ops-bob",
        "arn": "arn:aws:iam::123456789012:user/ops-bob",
        "policies": ["AssumeAdminPolicy"],
        "attachedPolicies": []
    }
    policy_docs = {
        "S3ReadPolicy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
        }),
        "AssumeAdminPolicy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::123456789012:role/OverlyTrustingAdminRole"
            }]
        })
    }

    res1 = evaluate_assume_role_trust_with_evidence(
        trust_policy_input=wildcard_role["trustPolicy"],
        role_name=wildcard_role["name"],
        role_arn=wildcard_role["arn"],
        all_users=[alice_unprivileged, bob_authorized],
        all_roles=[],
        account_id="123456789012",
        policy_doc_map=policy_docs,
    )

    definitive_users = [
        u for u in res1["users"]
        if u["evidence"].get("trust_status") == "definitive"
        and u["evidence"].get("call_permission_verified")
    ]
    definitive_names = {u["principal"]["name"] for u in definitive_users}

    # Check 1: alice must NOT receive CAN_ASSUME
    total_checks += 1
    if "developer-alice" not in definitive_names:
        passed_checks += 1
        print(f"{'aws:user:developer-alice':<25} | {'(NO EDGE)':<14} | {'aws:role:OverlyTrustingAdminRole':<25} | {'BLOCKED':<12} | Wildcard trust but NO call permission")
    else:
        print(f"{'aws:user:developer-alice':<25} | {'CAN_ASSUME':<14} | {'aws:role:OverlyTrustingAdminRole':<25} | {'FAILED':<12} | FALSE POSITIVE! Alice lacks assume perm")

    # Check 2: bob MUST receive CAN_ASSUME
    total_checks += 1
    if "ops-bob" in definitive_names:
        passed_checks += 1
        print(f"{'aws:user:ops-bob':<25} | {'CAN_ASSUME':<14} | {'aws:role:OverlyTrustingAdminRole':<25} | {'DEFINITIVE':<12} | Wildcard trust + verified call permission")
    else:
        print(f"{'aws:user:ops-bob':<25} | {'(NO EDGE)':<14} | {'aws:role:OverlyTrustingAdminRole':<25} | {'FAILED':<12} | FALSE NEGATIVE! Bob has valid assume perm")

    # ──────────────────────────────────────────────────────────────────────────
    # SCENARIO 2: Group-Inherited Assume Permission
    # ──────────────────────────────────────────────────────────────────────────
    charlie_user = {
        "name": "charlie-dev",
        "arn": "arn:aws:iam::123456789012:user/charlie-dev",
        "groups": ["SecurityTeam"],
        "policies": [],
        "attachedPolicies": []
    }
    groups = [
        {
            "GroupName": "SecurityTeam",
            "arn": "arn:aws:iam::123456789012:group/SecurityTeam",
            "attachedPolicies": ["SecTeamAssumePolicy"]
        }
    ]
    policy_docs["SecTeamAssumePolicy"] = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::123456789012:role/SecRole"
        }]
    })

    res2 = evaluate_assume_role_trust_with_evidence(
        trust_policy_input={"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]},
        role_name="SecRole",
        role_arn="arn:aws:iam::123456789012:role/SecRole",
        all_users=[charlie_user],
        all_roles=[],
        account_id="123456789012",
        policy_doc_map=policy_docs,
        all_groups=groups,
    )
    charlie_definitive = any(
        u["principal"]["name"] == "charlie-dev" and u["evidence"].get("trust_status") == "definitive"
        for u in res2["users"]
    )
    total_checks += 1
    if charlie_definitive:
        passed_checks += 1
        print(f"{'aws:user:charlie-dev':<25} | {'CAN_ASSUME':<14} | {'aws:role:SecRole':<25} | {'DEFINITIVE':<12} | Group-inherited assume permission verified")
    else:
        print(f"{'aws:user:charlie-dev':<25} | {'(NO EDGE)':<14} | {'aws:role:SecRole':<25} | {'FAILED':<12} | Group inheritance failed")

    # ──────────────────────────────────────────────────────────────────────────
    # SCENARIO 3: Explicit Deny Precedence
    # ──────────────────────────────────────────────────────────────────────────
    frank_user = {
        "name": "frank-denied",
        "arn": "arn:aws:iam::123456789012:user/frank-denied",
        "groups": ["SecurityTeam"],  # Grants Allow
        "policies": ["DenyAssumeSecRolePolicy"],  # Direct Deny
        "attachedPolicies": []
    }
    policy_docs["DenyAssumeSecRolePolicy"] = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::123456789012:role/SecRole"
        }]
    })

    res3 = evaluate_assume_role_trust_with_evidence(
        trust_policy_input={"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]},
        role_name="SecRole",
        role_arn="arn:aws:iam::123456789012:role/SecRole",
        all_users=[frank_user],
        all_roles=[],
        account_id="123456789012",
        policy_doc_map=policy_docs,
        all_groups=groups,
    )
    frank_allowed = any(u["principal"]["name"] == "frank-denied" for u in res3["users"])
    total_checks += 1
    if not frank_allowed:
        passed_checks += 1
        print(f"{'aws:user:frank-denied':<25} | {'(NO EDGE)':<14} | {'aws:role:SecRole':<25} | {'BLOCKED':<12} | Explicit Deny strictly overrides group Allow")
    else:
        print(f"{'aws:user:frank-denied':<25} | {'CAN_ASSUME':<14} | {'aws:role:SecRole':<25} | {'FAILED':<12} | Explicit Deny was ignored!")

    # ──────────────────────────────────────────────────────────────────────────
    # SCENARIO 4: Trust Policy Conditions (MFA, ExternalId, SourceIp)
    # ──────────────────────────────────────────────────────────────────────────
    mfa_role = {
        "name": "MfaRole",
        "arn": "arn:aws:iam::123456789012:role/MfaRole",
        "trustPolicy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/laura"},
                "Action": "sts:AssumeRole",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
            }]
        }
    }
    laura_user = {
        "name": "laura",
        "arn": "arn:aws:iam::123456789012:user/laura",
        "policies": [],
        "attachedPolicies": []
    }
    res4 = evaluate_assume_role_trust_with_evidence(
        trust_policy_input=mfa_role["trustPolicy"],
        role_name=mfa_role["name"],
        role_arn=mfa_role["arn"],
        all_users=[laura_user],
        all_roles=[],
        account_id="123456789012",
        policy_doc_map={},
    )
    laura_entry = res4["users"][0] if res4["users"] else None
    laura_is_conditional = (
        laura_entry is not None
        and laura_entry["evidence"]["trust_status"] == "conditional"
        and len(res4["conditional_trusts"]) == 1
    )
    total_checks += 1
    if laura_is_conditional:
        passed_checks += 1
        print(f"{'aws:user:laura':<25} | {'(CONDITIONAL)':<14} | {'aws:role:MfaRole':<25} | {'CONDITIONAL':<12} | MFA condition unresolved -> CONDITIONAL_TRUST (no graph edge)")
    else:
        print(f"{'aws:user:laura':<25} | {'CAN_ASSUME':<14} | {'aws:role:MfaRole':<25} | {'FAILED':<12} | Unresolved MFA condition created active edge!")

    # ──────────────────────────────────────────────────────────────────────────
    # SCENARIO 5: Blast Radius Calculation (Assets Only)
    # ──────────────────────────────────────────────────────────────────────────
    G_blast = nx.DiGraph()
    G_blast.add_node("usr-blast", label="analyst", type="User", riskScore=30)
    G_blast.add_node("grp-blast", label="SecGroup", type="Group")
    G_blast.add_node("rol-blast", label="CloudAdmin", type="Role", riskScore=85)
    G_blast.add_node("pol-blast", label="FullS3Access", type="Policy")
    G_blast.add_node("s3-asset-1", label="FinanceReports", type="S3", riskScore=80)
    G_blast.add_node("s3-asset-2", label="ClientData", type="S3", riskScore=90)
    G_blast.add_node("rds-asset-1", label="CustomerDb", type="RDS", riskScore=95)

    G_blast.add_edge("usr-blast", "rol-blast", label="CAN_ASSUME")
    G_blast.add_edge("rol-blast", "pol-blast", label="HAS_POLICY")
    G_blast.add_edge("pol-blast", "s3-asset-1", label="ALLOWS")
    G_blast.add_edge("pol-blast", "s3-asset-2", label="ALLOWS")
    G_blast.add_edge("pol-blast", "rds-asset-1", label="ALLOWS")

    desc, asset_count = compute_effective_blast_radius("usr-blast", G_blast)
    total_checks += 1
    if asset_count == 3:
        passed_checks += 1
        print(f"{'aws:user:analyst':<25} | {'BLAST_RADIUS':<14} | {'3 Cloud Assets':<25} | {'ACCURATE':<12} | Counted {asset_count} assets, excluded User/Group/Role/Policy")
    else:
        print(f"{'aws:user:analyst':<25} | {'BLAST_RADIUS':<14} | {f'{asset_count} nodes':<25} | {'FAILED':<12} | Inflated blast radius counted identity/privilege nodes!")

    print("-" * 115)
    print(f"RESULTS: {passed_checks}/{total_checks} diagnostic checks PASSED.")

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 15: CAN_ASSUME EVIDENCE DETAIL PRINTER
    # ──────────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 100)
    print(" PHASE 15 — CAN_ASSUME EVIDENCE INSPECTOR")
    print("=" * 100)
    for u in res1["users"]:
        ev = u.get("evidence", {})
        print(f"\n{u['principal']['name']}")
        print(f"  -> {wildcard_role['name']}")
        print(f"  trust={ev.get('trust_principal_type')}")
        print(f"  trust_status={ev.get('trust_status')}")
        print(f"  condition_status={ev.get('conditions_status')}")
        print(f"  identity_allow={ev.get('identity_policy_allow')}")
        print(f"  explicit_deny={ev.get('explicit_deny')}")
        print(f"  boundary={ev.get('boundary_status')}")
        print(f"  org_policy={ev.get('organization_policy_status')}")
        print(f"  final_status={ev.get('authorization_status')}")

    if passed_checks == total_checks:
        print("\n[SUCCESS] All IAM trust, condition, and attack path invariants are 100% SATISFIED.\n")
        return 0
    else:
        print("\n[FAILURE] Some diagnostic invariants were VIOLATED.\n")
        return 1


if __name__ == "__main__":
    sys.exit(run_diagnostics())
