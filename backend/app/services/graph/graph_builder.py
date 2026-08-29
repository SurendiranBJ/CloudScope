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
    """Build the Neo4j graph with stable unique IDs and real IAM policy AST analysis."""
    logger.info("Initializing Neo4j Graph DB update rebuild")
    try:
        account_id = get_account_id()

        # 1. Clear database elements safely for full synchronization
        execute_write("MATCH (n) DETACH DELETE n")

        # 2. Write Users
        for u in inventory.users:
            u_id = get_node_id("User", u['name'])
            execute_write(
                """
                MERGE (n:User {id: $id})
                SET n.label = $username,
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

        # 3. Write Groups
        for g in inventory.groups:
            g_id = get_node_id("Group", g['name'])
            execute_write(
                """
                MERGE (n:Group {id: $id})
                SET n.label = $name,
                    n.arn = $arn,
                    n.type = 'Group',
                    n.region = 'global'
                """,
                {"id": g_id, "name": g['name'], "arn": g['arn']}
            )

        # 4. Write Roles
        for r in inventory.roles:
            r_id = get_node_id("Role", r['name'])
            execute_write(
                """
                MERGE (n:Role {id: $id})
                SET n.label = $name,
                    n.arn = $arn,
                    n.trustPolicy = $trust,
                    n.riskScore = $riskScore,
                    n.description = $desc,
                    n.type = 'Role',
                    n.region = 'global',
                    n.status = $status,
                    n.owner = $owner
                """,
                {
                    "id": r_id,
                    "name": r['name'],
                    "arn": r['arn'],
                    "trust": r.get('trustPolicy', '{}'),
                    "riskScore": r.get('riskScore', 0),
                    "desc": r.get('description', ''),
                    "status": r.get('status', 'active'),
                    "owner": r.get('owner', account_id)
                }
            )

        # 5. Write Policies
        for p in inventory.policies:
            p_id = get_node_id("Policy", p['name'])
            execute_write(
                """
                MERGE (n:Policy {id: $id})
                SET n.label = $name,
                    n.arn = $arn,
                    n.document = $doc,
                    n.isManaged = $managed,
                    n.riskScore = $riskScore,
                    n.type = 'Policy'
                """,
                {
                    "id": p_id,
                    "name": p['name'],
                    "arn": p.get('arn', ''),
                    "doc": p.get('document', '{}'),
                    "managed": p.get('type') == 'aws-managed',
                    "riskScore": p.get('riskScore', 0)
                }
            )

        # 6. Write S3
        for s in inventory.s3:
            s_id = get_node_id("S3", s['name'])
            execute_write(
                """
                MERGE (n:S3 {id: $id})
                SET n.label = $name,
                    n.arn = $arn,
                    n.region = $reg,
                    n.riskScore = $riskScore,
                    n.status = $status,
                    n.owner = $owner,
                    n.type = 'S3'
                """,
                {
                    "id": s_id,
                    "name": s['name'],
                    "arn": s['arn'],
                    "reg": s.get('region', 'global'),
                    "riskScore": s.get('riskScore', 0),
                    "status": s.get('status', 'configured'),
                    "owner": s.get('owner', account_id)
                }
            )

        # 7. Write EC2
        for e in inventory.ec2:
            e_id = get_node_id("EC2", e['id'])
            execute_write(
                """
                MERGE (n:EC2 {id: $id})
                SET n.label = $name,
                    n.arn = $arn,
                    n.region = $reg,
                    n.riskScore = $riskScore,
                    n.status = $status,
                    n.owner = $owner,
                    n.type = 'EC2'
                """,
                {
                    "id": e_id,
                    "name": e['name'],
                    "arn": e['arn'],
                    "reg": e.get('region', 'unknown'),
                    "riskScore": e.get('riskScore', 0),
                    "status": e.get('status', 'active'),
                    "owner": e.get('owner', account_id)
                }
            )

        # 8. Write Lambda
        for l in inventory.lambdas:
            l_id = get_node_id("Lambda", l['name'])
            execute_write(
                """
                MERGE (n:Lambda {id: $id})
                SET n.label = $name,
                    n.arn = $arn,
                    n.region = $reg,
                    n.riskScore = $riskScore,
                    n.status = $status,
                    n.owner = $owner,
                    n.type = 'Lambda'
                """,
                {
                    "id": l_id,
                    "name": l['name'],
                    "arn": l['arn'],
                    "reg": l.get('region', 'unknown'),
                    "riskScore": l.get('riskScore', 0),
                    "status": l.get('status', 'configured'),
                    "owner": l.get('owner', account_id)
                }
            )

        # 9. Write Secrets
        for sec in inventory.secrets:
            sec_id = get_node_id("Secrets", sec['name'])
            execute_write(
                """
                MERGE (n:Secrets {id: $id})
                SET n.label = $name,
                    n.arn = $arn,
                    n.region = $reg,
                    n.riskScore = $riskScore,
                    n.status = $status,
                    n.owner = $owner,
                    n.type = 'Secrets'
                """,
                {
                    "id": sec_id,
                    "name": sec['name'],
                    "arn": sec['arn'],
                    "reg": sec.get('region', 'unknown'),
                    "riskScore": sec.get('riskScore', 0),
                    "status": sec.get('status', 'configured'),
                    "owner": sec.get('owner', account_id)
                }
            )

        # 10. Write RDS
        for rds in inventory.rds:
            rds_id = get_node_id("RDS", rds['name'])
            execute_write(
                """
                MERGE (n:RDS {id: $id})
                SET n.label = $name,
                    n.arn = $arn,
                    n.region = $reg,
                    n.riskScore = $riskScore,
                    n.status = $status,
                    n.owner = $owner,
                    n.type = 'RDS'
                """,
                {
                    "id": rds_id,
                    "name": rds['name'],
                    "arn": rds['arn'],
                    "reg": rds.get('region', 'unknown'),
                    "riskScore": rds.get('riskScore', 0),
                    "status": rds.get('status', 'available'),
                    "owner": rds.get('owner', account_id)
                }
            )

        # 11. Write DynamoDB
        for ddb in inventory.dynamodb:
            ddb_id = get_node_id("DynamoDB", ddb['name'])
            execute_write(
                """
                MERGE (n:DynamoDB {id: $id})
                SET n.label = $name,
                    n.arn = $arn,
                    n.region = $reg,
                    n.riskScore = $riskScore,
                    n.status = $status,
                    n.owner = $owner,
                    n.type = 'DynamoDB'
                """,
                {
                    "id": ddb_id,
                    "name": ddb['name'],
                    "arn": ddb['arn'],
                    "reg": ddb.get('region', 'unknown'),
                    "riskScore": ddb.get('riskScore', 0),
                    "status": ddb.get('status', 'active'),
                    "owner": ddb.get('owner', account_id)
                }
            )

        # --- Relationships ---

        # 1. Users -> Groups
        for u in inventory.users:
            u_id = get_node_id("User", u['name'])
            for g_name in u.get('groups', []):
                g_id = get_node_id("Group", g_name)
                execute_write(
                    """
                    MATCH (u:User {id: $uid}), (g:Group {id: $gid})
                    MERGE (u)-[:MEMBER_OF]->(g)
                    """,
                    {"uid": u_id, "gid": g_id}
                )

        # 2. Users -> Policies
        for u in inventory.users:
            u_id = get_node_id("User", u['name'])
            for p_name in u.get('policies', []):
                clean_name = p_name.replace('[inline] ', '')
                p_id = get_node_id("Policy", clean_name)
                execute_write(
                    """
                    MATCH (u:User {id: $uid}), (p:Policy {id: $pid})
                    MERGE (u)-[:HAS_POLICY]->(p)
                    """,
                    {"uid": u_id, "pid": p_id}
                )

        # 3. Groups -> Policies
        for g in inventory.groups:
            g_id = get_node_id("Group", g['name'])
            for p_name in g.get('attachedPolicies', []):
                clean_name = p_name.replace('[inline] ', '')
                p_id = get_node_id("Policy", clean_name)
                execute_write(
                    """
                    MATCH (g:Group {id: $gid}), (p:Policy {id: $pid})
                    MERGE (g)-[:HAS_POLICY]->(p)
                    """,
                    {"gid": g_id, "pid": p_id}
                )

        # 4. Roles -> Policies
        for r in inventory.roles:
            r_id = get_node_id("Role", r['name'])
            for p_name in r.get('attachedPolicies', []):
                clean_name = p_name.replace('[inline] ', '')
                p_id = get_node_id("Policy", clean_name)
                execute_write(
                    """
                    MATCH (r:Role {id: $rid}), (p:Policy {id: $pid})
                    MERGE (r)-[:HAS_POLICY]->(p)
                    """,
                    {"rid": r_id, "pid": p_id}
                )

        # 5. EC2 -> Roles (instance profile)
        for e in inventory.ec2:
            role_name = e.get('details', {}).get('iam_role_name', 'None')
            if role_name and role_name != 'None':
                e_id = get_node_id("EC2", e['id'])
                r_id = get_node_id("Role", role_name)
                execute_write(
                    """
                    MATCH (e:EC2 {id: $eid}), (r:Role {id: $rid})
                    MERGE (e)-[:ATTACHED_TO]->(r)
                    """,
                    {"eid": e_id, "rid": r_id}
                )

        # 6. Lambda -> Roles (execution role)
        for l in inventory.lambdas:
            role_name = l.get('details', {}).get('execution_role', 'None')
            if role_name and role_name != 'None':
                l_id = get_node_id("Lambda", l['name'])
                r_id = get_node_id("Role", role_name)
                execute_write(
                    """
                    MATCH (l:Lambda {id: $lid}), (r:Role {id: $rid})
                    MERGE (l)-[:EXECUTES_WITH]->(r)
                    """,
                    {"lid": l_id, "rid": r_id}
                )

        # 7. AssumeRole Trust Relationships: Users/Roles -> CAN_ASSUME -> Role
        for r in inventory.roles:
            r_id = get_node_id("Role", r['name'])
            trust_analysis = evaluate_assume_role_trust(
                r.get('trustPolicy', '{}'),
                r['name'],
                inventory.users,
                inventory.roles,
                account_id
            )
            # Link Users
            for u in trust_analysis["users"]:
                u_id = get_node_id("User", u['name'])
                execute_write(
                    """
                    MATCH (u:User {id: $uid}), (r:Role {id: $rid})
                    MERGE (u)-[:CAN_ASSUME]->(r)
                    """,
                    {"uid": u_id, "rid": r_id}
                )
            # Link Roles
            for src_r in trust_analysis["roles"]:
                src_r_id = get_node_id("Role", src_r['name'])
                execute_write(
                    """
                    MATCH (s:Role {id: $srid}), (t:Role {id: $trid})
                    MERGE (s)-[:CAN_ASSUME]->(t)
                    """,
                    {"srid": src_r_id, "trid": r_id}
                )

        # 8. Policy -> ALLOWS -> Resource via real IAM Policy Document Evaluation
        all_resources = (
            inventory.s3 + inventory.secrets + inventory.rds +
            inventory.dynamodb + inventory.ec2 + inventory.lambdas
        )

        for p in inventory.policies:
            p_id = get_node_id("Policy", p['name'])
            doc = p.get('document', '{}')
            allowed_res = evaluate_policy_allows_resources(doc, all_resources)
            for res in allowed_res:
                res_type = res.get('type')
                item_ident = res.get('id') if res_type == 'EC2' else (res.get('name') or res.get('id'))
                res_id = get_node_id(res_type, item_ident)
                execute_write(
                    f"""
                    MATCH (p:Policy {{id: $pid}}), (r:{res_type} {{id: $rid}})
                    MERGE (p)-[:ALLOWS]->(r)
                    """,
                    {"pid": p_id, "rid": res_id}
                )

        logger.info("Successfully populated all nodes and relationships inside Neo4j database")
    except Exception as e:
        logger.error(f"Failed to build graph in Neo4j: {str(e)}")
        raise e
