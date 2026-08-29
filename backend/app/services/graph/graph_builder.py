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
    evaluate_assume_role_trust
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

        # 6. Relationship: User -> Group (MEMBER_OF)
        for u in inventory.users:
            u_id = get_node_id("User", u['name'])
            for grp in u.get('groups', []):
                g_id = get_node_id("Group", grp)
                execute_write(
                    """
                    MATCH (u:User {id: $u_id}), (g:Group {id: $g_id})
                    MERGE (u)-[:MEMBER_OF]->(g)
                    """,
                    {"u_id": u_id, "g_id": g_id}
                )

        # 7. Relationship: Group -> Policy (HAS_POLICY)
        for g in inventory.groups:
            g_id = get_node_id("Group", g['name'])
            for pol in g.get('attachedPolicies', []):
                p_id = get_node_id("Policy", pol)
                execute_write(
                    """
                    MATCH (g:Group {id: $g_id}), (p:Policy {id: $p_id})
                    MERGE (g)-[:HAS_POLICY]->(p)
                    """,
                    {"g_id": g_id, "p_id": p_id}
                )

        # 8. Relationship: User -> Policy (HAS_POLICY)
        for u in inventory.users:
            u_id = get_node_id("User", u['name'])
            for pol in u.get('policies', []):
                p_id = get_node_id("Policy", pol)
                execute_write(
                    """
                    MATCH (u:User {id: $u_id}), (p:Policy {id: $p_id})
                    MERGE (u)-[:HAS_POLICY]->(p)
                    """,
                    {"u_id": u_id, "p_id": p_id}
                )

        # 9. Relationship: Role -> Policy (HAS_POLICY)
        for r in inventory.roles:
            r_id = get_node_id("Role", r['name'])
            for pol in r.get('attachedPolicies', []):
                p_id = get_node_id("Policy", pol)
                execute_write(
                    """
                    MATCH (r:Role {id: $r_id}), (p:Policy {id: $p_id})
                    MERGE (r)-[:HAS_POLICY]->(p)
                    """,
                    {"r_id": r_id, "p_id": p_id}
                )

        # 10. Relationship: User / Role -> Role (CAN_ASSUME) via AST Trust Evaluation
        for r in inventory.roles:
            r_id = get_node_id("Role", r['name'])
            trust_result = evaluate_assume_role_trust(
                r.get('trustPolicy', '{}'),
                r['name'],
                inventory.users,
                inventory.roles,
                account_id
            )
            for trusted_u in trust_result["users"]:
                u_id = get_node_id("User", trusted_u['name'])
                execute_write(
                    """
                    MATCH (u:User {id: $u_id}), (r:Role {id: $r_id})
                    MERGE (u)-[:CAN_ASSUME]->(r)
                    """,
                    {"u_id": u_id, "r_id": r_id}
                )
            for trusted_r in trust_result["roles"]:
                tr_id = get_node_id("Role", trusted_r['name'])
                execute_write(
                    """
                    MATCH (tr:Role {id: $tr_id}), (r:Role {id: $r_id})
                    MERGE (tr)-[:CAN_ASSUME]->(r)
                    """,
                    {"tr_id": tr_id, "r_id": r_id}
                )

        # 11. Relationship: Policy -> Target Resource (ALLOWS) via AST Evaluation
        all_resources: List[Dict[str, Any]] = (
            inventory.s3 + inventory.ec2 + inventory.lambdas +
            inventory.secrets + inventory.rds + inventory.dynamodb
        )
        for p in inventory.policies:
            p_id = get_node_id("Policy", p['name'])
            allowed_res = evaluate_policy_allows_resources(p.get('document', '{}'), all_resources)
            for res in allowed_res:
                rtype = res.get('type', 'Resource')
                res_node_id = get_node_id(rtype, res['name'])
                execute_write(
                    f"""
                    MATCH (p:Policy {{id: $p_id}}), (res:{rtype} {{id: $res_id}})
                    MERGE (p)-[:ALLOWS]->(res)
                    """,
                    {"p_id": p_id, "res_id": res_node_id}
                )

        # 12. Relationship: EC2 -> Role (CAN_ASSUME)
        for e in inventory.ec2:
            role_name = e.get('details', {}).get('iam_role_name', 'None')
            if role_name and role_name != 'None':
                e_id = get_node_id("EC2", e['name'])
                r_id = get_node_id("Role", role_name)
                execute_write(
                    """
                    MATCH (e:EC2 {id: $e_id}), (r:Role {id: $r_id})
                    MERGE (e)-[:CAN_ASSUME]->(r)
                    """,
                    {"e_id": e_id, "r_id": r_id}
                )

        logger.info("Neo4j idempotent synchronization completed successfully.")
    except Exception as e:
        logger.error(f"Error synchronizing Neo4j graph: {e}")
        raise e
