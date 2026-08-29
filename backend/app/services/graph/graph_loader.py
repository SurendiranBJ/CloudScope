import json
import logging
import networkx as nx
from typing import Any
from app.database import execute_read
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


def load_graph_from_neo4j() -> nx.DiGraph:
    """Sync Neo4j nodes and edges into an in-memory NetworkX directed graph."""
    logger.info("Syncing Neo4j nodes to in-memory NetworkX directed graph")
    G = nx.DiGraph()
    try:
        # 1. Fetch nodes
        nodes = execute_read(
            "MATCH (n) RETURN n.id as id, labels(n)[0] as type, n.label as label, "
            "n.riskScore as riskScore, n.arn as arn, n.description as desc"
        )
        for n in nodes:
            node_id = n['id']
            if node_id:
                G.add_node(
                    node_id,
                    type=n.get('type', 'Resource'),
                    label=n.get('label', node_id),
                    riskScore=n.get('riskScore', 0),
                    arn=n.get('arn', ''),
                    description=n.get('desc', '')
                )

        # 2. Fetch edges
        edges = execute_read(
            "MATCH (s)-[r]->(t) RETURN s.id as source, t.id as target, type(r) as label"
        )
        for e in edges:
            source = e['source']
            target = e['target']
            if source and target:
                G.add_edge(source, target, label=e.get('label', 'CONNECTED_TO'))

        logger.info(f"Loaded NetworkX Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    except Exception as e:
        logger.error(f"Failed to sync NetworkX graph from Neo4j: {str(e)}. Returning empty graph.")
    return G


def build_local_graph(inventory: Any) -> nx.DiGraph:
    """Build a NetworkX directed graph directly from scan inventory using the exact same

    stable unique IDs and policy evaluator rules as Neo4j.
    """
    G = nx.DiGraph()
    logger.info("Building local NetworkX graph from scan inventory using policy evaluator")

    account_id = get_account_id()

    # 1. Add User nodes
    for u in inventory.users:
        u_id = get_node_id("User", u['name'])
        G.add_node(
            u_id,
            type='User',
            label=u['name'],
            riskScore=u.get('riskScore', 0),
            arn=u['arn'],
            description=f"IAM User: {u['name']}"
        )

    # 2. Add Group nodes
    for g in inventory.groups:
        g_id = get_node_id("Group", g['name'])
        G.add_node(
            g_id,
            type='Group',
            label=g['name'],
            riskScore=0,
            arn=g['arn'],
            description=f"IAM Group: {g['name']}"
        )

    # 3. Add Role nodes
    for r in inventory.roles:
        r_id = get_node_id("Role", r['name'])
        G.add_node(
            r_id,
            type='Role',
            label=r['name'],
            riskScore=r.get('riskScore', 0),
            arn=r['arn'],
            description=r.get('description', '')
        )

    # 4. Add Policy nodes
    for p in inventory.policies:
        p_id = get_node_id("Policy", p['name'])
        G.add_node(
            p_id,
            type='Policy',
            label=p['name'],
            riskScore=p.get('riskScore', 0),
            arn=p.get('arn', ''),
            description=p.get('document', '')
        )

    # 5. Add S3 nodes
    for s in inventory.s3:
        s_id = get_node_id("S3", s['name'])
        G.add_node(
            s_id,
            type='S3',
            label=s['name'],
            riskScore=s.get('riskScore', 0),
            arn=s['arn'],
            description=f"S3 Bucket: {s['name']}"
        )

    # 6. Add EC2 nodes
    for e in inventory.ec2:
        e_id = get_node_id("EC2", e['id'])
        G.add_node(
            e_id,
            type='EC2',
            label=e['name'],
            riskScore=e.get('riskScore', 0),
            arn=e['arn'],
            description=f"EC2 Instance: {e['name']}"
        )

    # 7. Add Lambda nodes
    for l in inventory.lambdas:
        l_id = get_node_id("Lambda", l['name'])
        G.add_node(
            l_id,
            type='Lambda',
            label=l['name'],
            riskScore=l.get('riskScore', 0),
            arn=l['arn'],
            description=f"Lambda Function: {l['name']}"
        )

    # 8. Add Secrets nodes
    for sec in inventory.secrets:
        sec_id = get_node_id("Secrets", sec['name'])
        G.add_node(
            sec_id,
            type='Secrets',
            label=sec['name'],
            riskScore=sec.get('riskScore', 0),
            arn=sec['arn'],
            description=f"Secret: {sec['name']}"
        )

    # 9. Add RDS nodes
    for rds in inventory.rds:
        rds_id = get_node_id("RDS", rds['name'])
        G.add_node(
            rds_id,
            type='RDS',
            label=rds['name'],
            riskScore=rds.get('riskScore', 0),
            arn=rds['arn'],
            description=f"RDS Instance: {rds['name']}"
        )

    # 10. Add DynamoDB nodes
    for ddb in inventory.dynamodb:
        ddb_id = get_node_id("DynamoDB", ddb['name'])
        G.add_node(
            ddb_id,
            type='DynamoDB',
            label=ddb['name'],
            riskScore=ddb.get('riskScore', 0),
            arn=ddb['arn'],
            description=f"DynamoDB Table: {ddb['name']}"
        )

    # --- Build Relationships ---

    # 1. Users -> Groups
    for u in inventory.users:
        u_id = get_node_id("User", u['name'])
        for g_name in u.get('groups', []):
            g_id = get_node_id("Group", g_name)
            if G.has_node(u_id) and G.has_node(g_id):
                G.add_edge(u_id, g_id, label='MEMBER_OF')

    # 2. Users -> Policies
    for u in inventory.users:
        u_id = get_node_id("User", u['name'])
        for p_name in u.get('policies', []):
            clean_name = p_name.replace('[inline] ', '')
            p_id = get_node_id("Policy", clean_name)
            if G.has_node(u_id) and G.has_node(p_id):
                G.add_edge(u_id, p_id, label='HAS_POLICY')

    # 3. Groups -> Policies
    for g in inventory.groups:
        g_id = get_node_id("Group", g['name'])
        for p_name in g.get('attachedPolicies', []):
            clean_name = p_name.replace('[inline] ', '')
            p_id = get_node_id("Policy", clean_name)
            if G.has_node(g_id) and G.has_node(p_id):
                G.add_edge(g_id, p_id, label='HAS_POLICY')

    # 4. Roles -> Policies
    for r in inventory.roles:
        r_id = get_node_id("Role", r['name'])
        for p_name in r.get('attachedPolicies', []):
            clean_name = p_name.replace('[inline] ', '')
            p_id = get_node_id("Policy", clean_name)
            if G.has_node(r_id) and G.has_node(p_id):
                G.add_edge(r_id, p_id, label='HAS_POLICY')

    # 5. EC2 -> Roles (instance profile)
    for e in inventory.ec2:
        role_name = e.get('details', {}).get('iam_role_name', 'None')
        if role_name and role_name != 'None':
            e_id = get_node_id("EC2", e['id'])
            r_id = get_node_id("Role", role_name)
            if G.has_node(e_id) and G.has_node(r_id):
                G.add_edge(e_id, r_id, label='ATTACHED_TO')

    # 6. Lambda -> Roles (execution role)
    for l in inventory.lambdas:
        role_name = l.get('details', {}).get('execution_role', 'None')
        if role_name and role_name != 'None':
            l_id = get_node_id("Lambda", l['name'])
            r_id = get_node_id("Role", role_name)
            if G.has_node(l_id) and G.has_node(r_id):
                G.add_edge(l_id, r_id, label='EXECUTES_WITH')

    # 7. AssumeRole Trust: Users/Roles -> CAN_ASSUME -> Role
    for r in inventory.roles:
        r_id = get_node_id("Role", r['name'])
        trust_analysis = evaluate_assume_role_trust(
            r.get('trustPolicy', '{}'),
            r['name'],
            inventory.users,
            inventory.roles,
            account_id
        )
        for u in trust_analysis["users"]:
            u_id = get_node_id("User", u['name'])
            if G.has_node(u_id) and G.has_node(r_id):
                G.add_edge(u_id, r_id, label='CAN_ASSUME')
        for src_r in trust_analysis["roles"]:
            src_r_id = get_node_id("Role", src_r['name'])
            if G.has_node(src_r_id) and G.has_node(r_id) and src_r_id != r_id:
                G.add_edge(src_r_id, r_id, label='CAN_ASSUME')

    # 8. Policy -> ALLOWS -> Resource via policy_evaluator
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
            if G.has_node(p_id) and G.has_node(res_id):
                G.add_edge(p_id, res_id, label='ALLOWS')

    logger.info(f"Built local NetworkX Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G
