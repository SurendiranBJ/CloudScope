"""
CloudScope Safe & Idempotent Neo4j Graph Builder.

Builds graph topology in Neo4j using idempotent MERGE queries.
Preserves historical CloudTrail activity events and dynamic activity edges
WITHOUT performing destructive full-graph deletions.
"""

import json
import logging
from typing import Dict, Any, List
from app.database import execute_write
from app.services.scanner.inventory import AWSInventory
from app.services.attack.policy_evaluator import (
    evaluate_policy_allows_resources,
    evaluate_assume_role_trust,
    evaluate_assume_role_trust_with_evidence,
)
from app.services.aws.session import get_account_id

logger = logging.getLogger("scanner")


def get_node_id(res_type: str, item_id: str) -> str:
    """Generate a stable globally unique node ID for a given resource type and item identifier."""
    type_map = {
        "User": "aws:user",
        "Role": "aws:role",
        "Group": "aws:group",
        "Policy": "aws:policy",
        "S3": "aws:s3",
        "EC2": "aws:ec2",
        "Lambda": "aws:lambda",
        "RDS": "aws:rds",
        "DynamoDB": "aws:dynamodb",
        "Secrets": "aws:secret"
    }
    prefix = type_map.get(res_type, f"aws:{res_type.lower()}")
    return f"{prefix}:{item_id}"


def build_graph_in_neo4j(inventory: AWSInventory):
    """Build or update the Neo4j graph using idempotent MERGE operations.
    Preserves ActivityEvent nodes and dynamic CloudTrail edges.
    """
    logger.info("Synchronizing AWS Inventory into Neo4j graph (idempotent)")
    try:
        account_id = get_account_id()

        # 1. Write / Update Users (Idempotent MERGE)
        for u in inventory.users:
            u_id = get_node_id("User", u['name'])
            execute_write(
                """
                MERGE (n:User {id: $id})
                SET n.label = $username,
                    n.name = $username,
                    n.arn = $arn,
                    n.mfaEnabled = $mfa,
                    n.riskScore = $riskScore,
                    n.status = $status,
                    n.type = 'User',
                    n.region = 'global',
                    n.owner = $owner
                """,
                {
                    "id": u_id,
                    "username": u['name'],
                    "arn": u['arn'],
                    "mfa": u.get('mfaEnabled', False),
                    "riskScore": u.get('riskScore', 0),
                    "status": u.get('status', 'active'),
                    "owner": u.get('owner', account_id)
                }
            )

        # 2. Write / Update Groups
        for g in inventory.groups:
            g_id = get_node_id("Group", g['name'])
            execute_write(
                """
                MERGE (n:Group {id: $id})
                SET n.label = $name,
                    n.name = $name,
                    n.arn = $arn,
                    n.type = 'Group',
                    n.region = 'global'
                """,
                {"id": g_id, "name": g['name'], "arn": g['arn']}
            )

        # 3. Write / Update Roles
        for r in inventory.roles:
            r_id = get_node_id("Role", r['name'])
            execute_write(
                """
                MERGE (n:Role {id: $id})
                SET n.label = $name,
                    n.name = $name,
                    n.arn = $arn,
                    n.trustPolicy = $trust,
                    n.riskScore = $riskScore,
                    n.type = 'Role',
                    n.region = 'global'
                """,
                {
                    "id": r_id,
                    "name": r['name'],
                    "arn": r['arn'],
                    "trust": r.get('trustPolicy', '{}'),
                    "riskScore": r.get('riskScore', 0)
                }
            )

        # 4. Write / Update Policies
        for p in inventory.policies:
            p_id = get_node_id("Policy", p['name'])
            doc_val = p.get('document', '{}')
            doc_str = json.dumps(doc_val) if isinstance(doc_val, dict) else str(doc_val)
            execute_write(
                """
                MERGE (n:Policy {id: $id})
                SET n.label = $name,
                    n.name = $name,
                    n.arn = $arn,
                    n.policyType = $ptype,
                    n.document = $doc,
                    n.type = 'Policy',
                    n.region = 'global'
                """,
                {
                    "id": p_id,
                    "name": p['name'],
                    "arn": p.get('arn', ''),
                    "ptype": p.get('type', 'managed'),
                    "doc": doc_str
                }
            )

        # 5. Write / Update Cloud Resources
        for s in inventory.s3:
            s_id = get_node_id("S3", s['name'])
            execute_write(
                """
                MERGE (n:S3 {id: $id})
                SET n.label = $name,
                    n.name = $name,
                    n.arn = $arn,
                    n.riskScore = $riskScore,
                    n.type = 'S3',
                    n.region = $region
                """,
                {
                    "id": s_id,
                    "name": s['name'],
                    "arn": s.get('arn', f"arn:aws:s3:::{s['name']}"),
                    "riskScore": s.get('riskScore', 0),
                    "region": s.get('region', 'global')
                }
            )

        for e in inventory.ec2:
            e_id = get_node_id("EC2", e['name'])
            execute_write(
                """
                MERGE (n:EC2 {id: $id})
                SET n.label = $name,
                    n.name = $name,
                    n.arn = $arn,
                    n.riskScore = $riskScore,
                    n.type = 'EC2',
                    n.region = $region
                """,
                {
                    "id": e_id,
                    "name": e['name'],
                    "arn": e.get('arn', ''),
                    "riskScore": e.get('riskScore', 0),
                    "region": e.get('region', 'us-east-1')
                }
            )

        for l_fn in inventory.lambdas:
            l_id = get_node_id("Lambda", l_fn['name'])
            execute_write(
                """
                MERGE (n:Lambda {id: $id})
                SET n.label = $name,
                    n.name = $name,
                    n.arn = $arn,
                    n.riskScore = $riskScore,
                    n.type = 'Lambda',
                    n.region = $region
                """,
                {
                    "id": l_id,
                    "name": l_fn['name'],
                    "arn": l_fn.get('arn', ''),
                    "riskScore": l_fn.get('riskScore', 0),
                    "region": l_fn.get('region', 'us-east-1')
                }
            )

        for sec in inventory.secrets:
            sec_id = get_node_id("Secrets", sec['name'])
            execute_write(
                """
                MERGE (n:Secrets {id: $id})
                SET n.label = $name,
                    n.name = $name,
                    n.arn = $arn,
                    n.riskScore = $riskScore,
                    n.type = 'Secrets',
                    n.region = $region
                """,
                {
                    "id": sec_id,
                    "name": sec['name'],
                    "arn": sec.get('arn', ''),
                    "riskScore": sec.get('riskScore', 0),
                    "region": sec.get('region', 'us-east-1')
                }
            )

        for rds in inventory.rds:
            rds_id = get_node_id("RDS", rds['name'])
            execute_write(
                """
                MERGE (n:RDS {id: $id})
                SET n.label = $name,
                    n.name = $name,
                    n.arn = $arn,
                    n.riskScore = $riskScore,
                    n.type = 'RDS',
                    n.region = $region
                """,
                {
                    "id": rds_id,
                    "name": rds['name'],
                    "arn": rds.get('arn', ''),
                    "riskScore": rds.get('riskScore', 0),
                    "region": rds.get('region', 'us-east-1')
                }
            )

        for ddb in inventory.dynamodb:
            ddb_id = get_node_id("DynamoDB", ddb['name'])
            execute_write(
                """
                MERGE (n:DynamoDB {id: $id})
                SET n.label = $name,
                    n.name = $name,
                    n.arn = $arn,
                    n.riskScore = $riskScore,
                    n.type = 'DynamoDB',
                    n.region = $region
                """,
                {
                    "id": ddb_id,
                    "name": ddb['name'],
                    "arn": ddb.get('arn', ''),
                    "riskScore": ddb.get('riskScore', 0),
                    "region": ddb.get('region', 'us-east-1')
                }
            )

        # 6. Relationship: User -> Group (MEMBER_OF) + Reconciliation
        for u in inventory.users:
            u_id = get_node_id("User", u['name'])
            valid_g_ids = [get_node_id("Group", grp) for grp in u.get('groups', [])]
            execute_write(
                """
                MATCH (u:User {id: $u_id})-[rel:MEMBER_OF]->(g:Group)
                WHERE NOT g.id IN $valid_g_ids
                DELETE rel
                """,
                {"u_id": u_id, "valid_g_ids": valid_g_ids}
            )
            for g_id in valid_g_ids:
                execute_write(
                    """
                    MATCH (u:User {id: $u_id}), (g:Group {id: $g_id})
                    MERGE (u)-[:MEMBER_OF]->(g)
                    """,
                    {"u_id": u_id, "g_id": g_id}
                )

        # 7. Relationship: Group -> Policy (HAS_POLICY) + Reconciliation
        for g in inventory.groups:
            g_id = get_node_id("Group", g['name'])
            valid_p_ids = [get_node_id("Policy", pol.replace('[inline] ', '')) for pol in g.get('attachedPolicies', [])]
            execute_write(
                """
                MATCH (g:Group {id: $g_id})-[rel:HAS_POLICY]->(p:Policy)
                WHERE NOT p.id IN $valid_p_ids
                DELETE rel
                """,
                {"g_id": g_id, "valid_p_ids": valid_p_ids}
            )
            for p_id in valid_p_ids:
                execute_write(
                    """
                    MATCH (g:Group {id: $g_id}), (p:Policy {id: $p_id})
                    MERGE (g)-[:HAS_POLICY]->(p)
                    """,
                    {"g_id": g_id, "p_id": p_id}
                )

        # 8. Relationship: User -> Policy (HAS_POLICY) + Reconciliation
        for u in inventory.users:
            u_id = get_node_id("User", u['name'])
            valid_p_ids = [get_node_id("Policy", pol.replace('[inline] ', '')) for pol in u.get('policies', [])]
            execute_write(
                """
                MATCH (u:User {id: $u_id})-[rel:HAS_POLICY]->(p:Policy)
                WHERE NOT p.id IN $valid_p_ids
                DELETE rel
                """,
                {"u_id": u_id, "valid_p_ids": valid_p_ids}
            )
            for p_id in valid_p_ids:
                execute_write(
                    """
                    MATCH (u:User {id: $u_id}), (p:Policy {id: $p_id})
                    MERGE (u)-[:HAS_POLICY]->(p)
                    """,
                    {"u_id": u_id, "p_id": p_id}
                )

        # 9. Relationship: Role -> Policy (HAS_POLICY) + Reconciliation
        for r in inventory.roles:
            r_id = get_node_id("Role", r['name'])
            valid_p_ids = [get_node_id("Policy", pol.replace('[inline] ', '')) for pol in r.get('attachedPolicies', [])]
            execute_write(
                """
                MATCH (r:Role {id: $r_id})-[rel:HAS_POLICY]->(p:Policy)
                WHERE NOT p.id IN $valid_p_ids
                DELETE rel
                """,
                {"r_id": r_id, "valid_p_ids": valid_p_ids}
            )
            for p_id in valid_p_ids:
                execute_write(
                    """
                    MATCH (r:Role {id: $r_id}), (p:Policy {id: $p_id})
                    MERGE (r)-[:HAS_POLICY]->(p)
                    """,
                    {"r_id": r_id, "p_id": p_id}
                )

        # 10. Relationship: User / Role -> Role (CAN_ASSUME) — definitive evidence-verified only + Reconciliation
        _policy_doc_map = {}
        for _p in inventory.policies:
            if _p.get('name') and _p.get('document'):
                _policy_doc_map[_p['name']] = _p['document']

        all_valid_role_ids = [get_node_id("Role", r['name']) for r in inventory.roles]
        execute_write(
            """
            MATCH ()-[rel:CAN_ASSUME]->(r:Role)
            WHERE NOT r.id IN $all_valid_role_ids
            DELETE rel
            """,
            {"all_valid_role_ids": all_valid_role_ids}
        )

        for r in inventory.roles:
            r_id = get_node_id("Role", r['name'])
            r_arn = r.get('arn', '')

            trust_ev = evaluate_assume_role_trust_with_evidence(
                r.get('trustPolicy', '{}'),
                r['name'],
                r_arn,
                inventory.users,
                inventory.roles,
                account_id,
                _policy_doc_map,
                all_groups=inventory.groups,
            )

            # Annotate Role node with trust metadata in Neo4j (always reset to clean state)
            execute_write(
                """
                MATCH (r:Role {id: $r_id})
                SET r.trust_is_broad = $tib,
                    r.trust_principal_types = $tpt,
                    r.has_conditional_trust = $hct,
                    r.conditional_trust_count = $ctc
                """,
                {
                    "r_id": r_id,
                    "tib": bool(trust_ev.get('trust_is_broad', False)),
                    "tpt": ','.join(sorted(trust_ev.get('trust_principal_types', set()))),
                    "hct": bool(trust_ev.get('conditional_trusts', [])),
                    "ctc": len(trust_ev.get('conditional_trusts', [])),
                }
            )

            # Compute currently valid definitive source IDs
            valid_source_ids = []
            valid_user_entries = []
            for entry in trust_ev.get('users', []):
                if entry['evidence'].get('trust_status') != 'definitive':
                    continue
                if not entry['evidence'].get('call_permission_verified'):
                    continue
                trusted_u = entry['principal']
                u_id = get_node_id("User", trusted_u['name'])
                valid_source_ids.append(u_id)
                valid_user_entries.append((u_id, entry['evidence']['trust_principal_type']))

            valid_role_entries = []
            for entry in trust_ev.get('roles', []):
                if entry['evidence'].get('trust_status') != 'definitive':
                    continue
                if not entry['evidence'].get('call_permission_verified'):
                    continue
                trusted_r = entry['principal']
                tr_id = get_node_id("Role", trusted_r['name'])
                if tr_id != r_id:
                    valid_source_ids.append(tr_id)
                    valid_role_entries.append((tr_id, entry['evidence']['trust_principal_type']))

            # Reconcile: delete stale CAN_ASSUME edges targeting this role
            execute_write(
                """
                MATCH (s)-[rel:CAN_ASSUME]->(r:Role {id: $r_id})
                WHERE NOT s.id IN $valid_source_ids
                DELETE rel
                """,
                {"r_id": r_id, "valid_source_ids": valid_source_ids}
            )

            # Merge valid CAN_ASSUME edges
            for u_id, t_type in valid_user_entries:
                execute_write(
                    """
                    MATCH (u:User {id: $u_id}), (r:Role {id: $r_id})
                    MERGE (u)-[rel:CAN_ASSUME]->(r)
                    SET rel.trust_type = $trust_type
                    """,
                    {"u_id": u_id, "r_id": r_id, "trust_type": t_type}
                )

            for tr_id, t_type in valid_role_entries:
                execute_write(
                    """
                    MATCH (tr:Role {id: $tr_id}), (r:Role {id: $r_id})
                    MERGE (tr)-[rel:CAN_ASSUME]->(r)
                    SET rel.trust_type = $trust_type
                    """,
                    {"tr_id": tr_id, "r_id": r_id, "trust_type": t_type}
                )

        # 11. Relationship: Policy -> Target Resource (ALLOWS) via AST Evaluation + Reconciliation
        all_resources: List[Dict[str, Any]] = (
            inventory.s3 + inventory.ec2 + inventory.lambdas +
            inventory.secrets + inventory.rds + inventory.dynamodb
        )
        for p in inventory.policies:
            p_id = get_node_id("Policy", p['name'])
            allowed_res = evaluate_policy_allows_resources(p.get('document', '{}'), all_resources)
            valid_res_node_ids = []
            for res in allowed_res:
                rtype = res.get('type', 'Resource')
                valid_res_node_ids.append(get_node_id(rtype, res['name']))

            execute_write(
                """
                MATCH (p:Policy {id: $p_id})-[rel:ALLOWS]->(res)
                WHERE NOT res.id IN $valid_res_node_ids
                DELETE rel
                """,
                {"p_id": p_id, "valid_res_node_ids": valid_res_node_ids}
            )

            for res_node_id in valid_res_node_ids:
                execute_write(
                    """
                    MATCH (p:Policy {id: $p_id}), (res {id: $res_id})
                    MERGE (p)-[:ALLOWS]->(res)
                    """,
                    {"p_id": p_id, "res_id": res_node_id}
                )

        # 12. Relationship: EC2 -> Role (ATTACHED_TO) + Reconciliation
        for e in inventory.ec2:
            e_id = get_node_id("EC2", e['name'])
            role_name = e.get('details', {}).get('iam_role_name', 'None')
            valid_r_ids = []
            if role_name and role_name != 'None':
                valid_r_ids = [get_node_id("Role", role_name)]

            execute_write(
                """
                MATCH (e:EC2 {id: $e_id})-[rel:ATTACHED_TO]->(r:Role)
                WHERE NOT r.id IN $valid_r_ids
                DELETE rel
                """,
                {"e_id": e_id, "valid_r_ids": valid_r_ids}
            )
            for r_id in valid_r_ids:
                execute_write(
                    """
                    MATCH (e:EC2 {id: $e_id}), (r:Role {id: $r_id})
                    MERGE (e)-[:ATTACHED_TO]->(r)
                    """,
                    {"e_id": e_id, "r_id": r_id}
                )

        # 13. Relationship: Lambda -> Role (EXECUTES_WITH) + Reconciliation
        for l in inventory.lambdas:
            l_id = get_node_id("Lambda", l['name'])
            exec_role = l.get('details', {}).get('execution_role', 'None')
            valid_r_ids = []
            if exec_role and exec_role != 'None':
                valid_r_ids = [get_node_id("Role", exec_role)]

            execute_write(
                """
                MATCH (l:Lambda {id: $l_id})-[rel:EXECUTES_WITH]->(r:Role)
                WHERE NOT r.id IN $valid_r_ids
                DELETE rel
                """,
                {"l_id": l_id, "valid_r_ids": valid_r_ids}
            )
            for r_id in valid_r_ids:
                execute_write(
                    """
                    MATCH (l:Lambda {id: $l_id}), (r:Role {id: $r_id})
                    MERGE (l)-[:EXECUTES_WITH]->(r)
                    """,
                    {"l_id": l_id, "r_id": r_id}
                )

        # 14. Configuration Node Reconciliation: prune stale AWS inventory nodes
        # Strictly preserves historical CloudTrail (:ActivityEvent) nodes and edges
        node_type_specs = [
            ("User", [get_node_id("User", u['name']) for u in inventory.users]),
            ("Group", [get_node_id("Group", g['name']) for g in inventory.groups]),
            ("Role", [get_node_id("Role", r['name']) for r in inventory.roles]),
            ("Policy", [get_node_id("Policy", p['name']) for p in inventory.policies]),
            ("S3", [get_node_id("S3", s['name']) for s in inventory.s3]),
            ("EC2", [get_node_id("EC2", e['name']) for e in inventory.ec2]),
            ("Lambda", [get_node_id("Lambda", l['name']) for l in inventory.lambdas]),
            ("Secrets", [get_node_id("Secrets", s['name']) for s in inventory.secrets]),
            ("RDS", [get_node_id("RDS", r['name']) for r in inventory.rds]),
            ("DynamoDB", [get_node_id("DynamoDB", d['name']) for d in inventory.dynamodb]),
        ]

        for label, valid_ids in node_type_specs:
            execute_write(
                f"""
                MATCH (n:{label})
                WHERE NOT n.id IN $valid_ids
                DETACH DELETE n
                """,
                {"valid_ids": valid_ids}
            )

        logger.info("Neo4j idempotent synchronization completed successfully.")
    except Exception as e:
        logger.error(f"Error synchronizing Neo4j graph: {e}")
        raise e
