import logging
import json
import networkx as nx
from app.database import execute_read

logger = logging.getLogger("scanner")


def load_graph_from_neo4j() -> nx.DiGraph:
    logger.info("Syncing Neo4j nodes to in-memory NetworkX directed graph")
    G = nx.DiGraph()
    try:
        # 1. Fetch nodes
        nodes = execute_read("MATCH (n) RETURN n.id as id, labels(n)[0] as type, n.label as label, n.riskScore as riskScore, n.arn as arn, n.description as desc")
        for n in nodes:
            node_id = n['id']
            if node_id:
                G.add_node(
                    node_id,
                    type=n['type'],
                    label=n.get('label', node_id),
                    riskScore=n.get('riskScore', 0),
                    arn=n.get('arn', ''),
                    description=n.get('desc', '')
                )

        # 2. Fetch edges
        edges = execute_read("MATCH (s)-[r]->(t) RETURN s.id as source, t.id as target, type(r) as label")
        for e in edges:
            source = e['source']
            target = e['target']
            if source and target:
                G.add_edge(source, target, label=e.get('label', 'CONNECTED_TO'))

        logger.info(f"Loaded NetworkX Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    except Exception as e:
        logger.error(f"Failed to sync NetworkX graph from Neo4j: {str(e)}. Returning empty graph.")
    return G


def build_local_graph(inventory) -> nx.DiGraph:
    """Build a NetworkX directed graph directly from scan inventory data without Neo4j."""
    G = nx.DiGraph()
    logger.info("Building local NetworkX graph from scan inventory")

    # 1. Add User nodes
    for u in inventory.users:
        G.add_node(u['id'], type='User', label=u['name'], riskScore=u.get('riskScore', 0),
                   arn=u['arn'], description=f"IAM User: {u['name']}")

    # 2. Add Group nodes
    for g in inventory.groups:
        G.add_node(g['id'], type='Group', label=g['name'], riskScore=0,
                   arn=g['arn'], description=f"IAM Group: {g['name']}")

    # 3. Add Role nodes
    for r in inventory.roles:
        G.add_node(r['name'], type='Role', label=r['name'], riskScore=r.get('riskScore', 0),
                   arn=r['arn'], description=r.get('description', ''))

    # 4. Add Policy nodes
    for p in inventory.policies:
        G.add_node(p['name'], type='Policy', label=p['name'], riskScore=p.get('riskScore', 0),
                   arn=p['arn'], description='')

    # 5. Add S3 nodes
    for s in inventory.s3:
        G.add_node(s['id'], type='S3', label=s['name'], riskScore=s.get('riskScore', 0),
                   arn=s['arn'], description=f"S3 Bucket: {s['name']}")

    # 6. Add EC2 nodes
    for e in inventory.ec2:
        G.add_node(e['id'], type='EC2', label=e['name'], riskScore=e.get('riskScore', 0),
                   arn=e['arn'], description=f"EC2 Instance: {e['name']}")

    # 7. Add Lambda nodes
    for l in inventory.lambdas:
        G.add_node(l['id'], type='Lambda', label=l['name'], riskScore=l.get('riskScore', 0),
                   arn=l['arn'], description=f"Lambda Function: {l['name']}")

    # 8. Add Secrets nodes
    for sec in inventory.secrets:
        G.add_node(sec['id'], type='Secrets', label=sec['name'], riskScore=sec.get('riskScore', 0),
                   arn=sec['arn'], description=f"Secret: {sec['name']}")

    # --- Build Relationships ---

    # Group name -> Group ID lookup
    group_id_map = {g['name']: g['id'] for g in inventory.groups}

    # Users -> Groups
    for u in inventory.users:
        for g_name in u.get('groups', []):
            g_id = group_id_map.get(g_name)
            if g_id and G.has_node(g_id):
                G.add_edge(u['id'], g_id, label='MEMBER_OF')

    # Users -> Policies (only non-inline, matching existing policy nodes)
    for u in inventory.users:
        for p_name in u.get('policies', []):
            clean_name = p_name.replace('[inline] ', '')
            if G.has_node(clean_name):
                G.add_edge(u['id'], clean_name, label='HAS_POLICY')

    # Roles -> their attached policies
    for r in inventory.roles:
        for p_name in r.get('attachedPolicies', []):
            if G.has_node(p_name):
                G.add_edge(r['name'], p_name, label='HAS_POLICY')

    # Roles -> Roles (trust policy: who can assume this role)
    role_name_set = {r['name'] for r in inventory.roles}
    for r in inventory.roles:
        try:
            trust = json.loads(r.get('trustPolicy', '{}'))
            statements = trust.get('Statement', [])
            for stmt in statements:
                if stmt.get('Effect') == 'Allow' and 'AssumeRole' in str(stmt.get('Action', '')):
                    principal = stmt.get('Principal', {})
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    for p_arn in aws_principals:
                        # Extract role/user name from principal ARN
                        if ':role/' in p_arn:
                            source_name = p_arn.split('/')[-1]
                            if source_name in role_name_set and source_name != r['name']:
                                G.add_edge(source_name, r['name'], label='CAN_ASSUME')
                        elif ':user/' in p_arn:
                            source_name = p_arn.split('/')[-1]
                            # Find user ID by name
                            for u in inventory.users:
                                if u['name'] == source_name:
                                    G.add_edge(u['id'], r['name'], label='CAN_ASSUME')
                                    break
                        elif ':root' in p_arn or p_arn == '*':
                            # Entire account or wildcard can assume
                            pass
        except (json.JSONDecodeError, Exception):
            pass

    # EC2 -> Roles (instance profile)
    for e in inventory.ec2:
        role_name = e.get('details', {}).get('iam_role_name', 'None')
        if role_name != 'None' and G.has_node(role_name):
            G.add_edge(e['id'], role_name, label='ATTACHED_TO')

    # Lambda -> Roles (execution role)
    for l in inventory.lambdas:
        role_name = l.get('details', {}).get('execution_role', 'None')
        if role_name != 'None' and G.has_node(role_name):
            G.add_edge(l['id'], role_name, label='EXECUTES_WITH')

    # Roles -> Resources (connect roles with broad access policies to S3/Secrets)
    # Heuristic: if a role has policies with 's3' or 'secretsmanager' in name, connect to those resources
    for r in inventory.roles:
        for p_name in r.get('attachedPolicies', []):
            p_lower = p_name.lower()
            if 's3' in p_lower or 'storage' in p_lower or 'admin' in p_lower:
                for s in inventory.s3:
                    G.add_edge(r['name'], s['id'], label='ALLOWS')
            if 'secret' in p_lower or 'admin' in p_lower:
                for sec in inventory.secrets:
                    G.add_edge(r['name'], sec['id'], label='ALLOWS')

    # Users -> Resources (connect users with broad access policies to S3/Secrets)
    for u in inventory.users:
        for p_name in u.get('policies', []):
            p_lower = p_name.lower()
            if 's3' in p_lower or 'storage' in p_lower or 'admin' in p_lower:
                for s in inventory.s3:
                    G.add_edge(u['id'], s['id'], label='ALLOWS')
            if 'secret' in p_lower or 'admin' in p_lower:
                for sec in inventory.secrets:
                    G.add_edge(u['id'], sec['id'], label='ALLOWS')

    logger.info(f"Built local NetworkX Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G
