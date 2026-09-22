import json
import logging
import networkx as nx
from typing import Any, List, Dict, Set, Tuple, Optional
from app.database import execute_read
from app.services.attack.policy_evaluator import (
    evaluate_policy_allows_resources,
    evaluate_policy_allows_resources_with_provenance,
    evaluate_assume_role_trust,
    evaluate_assume_role_trust_with_evidence,
)
from app.services.aws.session import get_account_id
from app.services.graph.edge_validation import validate_edge
from app.services.scanner.inventory import AWSInventory

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
        "Secrets": "aws:secret",
        "AuroraDBUser": "aws:dbuser",
        "DBUser": "aws:dbuser"
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
                lbl = e.get('label') or ''
                if lbl:
                    G.add_edge(source, target, label=lbl)

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

    if isinstance(inventory, dict):
        inv = AWSInventory()
        inv.users = [
            {
                "name": u.get("name") or u.get("UserName"),
                "arn": u.get("arn") or u.get("Arn"),
                "groups": u.get("groups") or u.get("Groups", []),
                "policies": [
                    p.get("name") or p.get("PolicyName") if isinstance(p, dict) else p
                    for p in (u.get("policies") or u.get("AttachedPolicies", []))
                ],
                "attached_policies": u.get("AttachedPolicies") or u.get("attached_policies", [])
            }
            for u in (inventory.get("iam_users") or inventory.get("users", []))
        ]
        inv.groups = [
            {
                "name": g.get("name") or g.get("GroupName"),
                "arn": g.get("arn") or g.get("Arn"),
                "policies": [
                    p.get("name") or p.get("PolicyName") if isinstance(p, dict) else p
                    for p in (g.get("policies") or g.get("AttachedPolicies", []))
                ]
            }
            for g in (inventory.get("iam_groups") or inventory.get("groups", []))
        ]
        inv.roles = [
            {
                "name": r.get("name") or r.get("RoleName"),
                "arn": r.get("arn") or r.get("Arn"),
                "trustPolicy": r.get("trustPolicy") or r.get("AssumeRolePolicyDocument", {}),
                "attachedPolicies": [
                    p.get("name") or p.get("PolicyName") if isinstance(p, dict) else p
                    for p in (r.get("attachedPolicies") or r.get("AttachedPolicies", []))
                ],
                "riskScore": r.get("riskScore", 0)
            }
            for r in (inventory.get("iam_roles") or inventory.get("roles", []))
        ]
        raw_pols = inventory.get("iam_policies") or inventory.get("policies", [])
        inv.policies = [
            {
                "name": p.get("name") or p.get("PolicyName"),
                "arn": p.get("arn") or p.get("PolicyArn", ""),
                "document": p.get("document") or p.get("PolicyDocument", {})
            }
            for p in raw_pols
        ]
        # Harvest attached policies from users, groups, and roles if not already in inv.policies
        existing_pol_names = {p["name"] for p in inv.policies}
        for u in (inventory.get("iam_users") or inventory.get("users", [])):
            for ap in (u.get("AttachedPolicies") or u.get("attached_policies") or []):
                if isinstance(ap, dict) and ap.get("PolicyName") and ap.get("PolicyName") not in existing_pol_names:
                    inv.policies.append({
                        "name": ap["PolicyName"],
                        "arn": ap.get("PolicyArn", ""),
                        "document": ap.get("PolicyDocument", {})
                    })
                    existing_pol_names.add(ap["PolicyName"])
        for r in (inventory.get("iam_roles") or inventory.get("roles", [])):
            for ap in (r.get("AttachedPolicies") or r.get("attached_policies") or []):
                if isinstance(ap, dict) and ap.get("PolicyName") and ap.get("PolicyName") not in existing_pol_names:
                    inv.policies.append({
                        "name": ap["PolicyName"],
                        "arn": ap.get("PolicyArn", ""),
                        "document": ap.get("PolicyDocument", {})
                    })
                    existing_pol_names.add(ap["PolicyName"])

        s3_items = [
            {"name": b.get("name") or b.get("Name"), "arn": b.get("arn") or b.get("Arn") or f"arn:aws:s3:::{b.get('name') or b.get('Name')}", "region": b.get("region", "us-east-1")}
            for b in (inventory.get("s3_buckets") or inventory.get("s3", []))
        ]
        inv.s3 = s3_items
        inv.s3_buckets = s3_items

        ec2_raw = inventory.get("ec2_instances") or inventory.get("ec2", [])
        ec2_items = []
        for e in ec2_raw:
            eid = e.get("id") or e.get("InstanceId") or e.get("name")
            ename = e.get("name") or e.get("InstanceId") or eid
            earn = e.get("arn") or f"arn:aws:ec2:{e.get('region', 'us-east-1')}:instance/{eid}"
            profile = e.get("IamInstanceProfile") or {}
            profile_arn = profile.get("Arn") if isinstance(profile, dict) else str(profile)
            r_name = profile_arn.split("/")[-1] if profile_arn else e.get("role")
            details = dict(e.get("details", {}))
            if r_name:
                details["iam_role_name"] = r_name
            state_val = e.get("State") or e.get("state")
            state_name = state_val.get("Name") if isinstance(state_val, dict) else (state_val or "running")
            ec2_items.append({
                "id": eid,
                "name": ename,
                "arn": earn,
                "region": e.get("region", "us-east-1"),
                "role": r_name,
                "details": details,
                "state": state_name
            })
        inv.ec2 = ec2_items
        inv.ec2_instances = ec2_items

        lambda_items = inventory.get("lambda_functions") or inventory.get("lambdas", [])
        inv.lambdas = lambda_items
        inv.lambda_functions = lambda_items

        inv.secrets = inventory.get("secrets", [])

        rds_raw = inventory.get("rds_instances") or inventory.get("rds", [])
        rds_items = []
        for r in rds_raw:
            rname = r.get("name") or r.get("DBInstanceIdentifier") or r.get("DBClusterIdentifier") or r.get("id")
            rarn = r.get("arn") or r.get("Arn") or f"arn:aws:rds:{r.get('region', 'us-east-1')}:db:{rname}"
            rds_items.append({
                "name": rname,
                "arn": rarn,
                "region": r.get("region", "us-east-1"),
                "IAMDatabaseAuthenticationEnabled": r.get("IAMDatabaseAuthenticationEnabled", False),
                "details": r.get("details", {})
            })
        inv.rds = rds_items
        inv.rds_instances = rds_items

        ddb_items = inventory.get("dynamodb_tables") or inventory.get("dynamodb", [])
        inv.dynamodb = ddb_items
        inv.dynamodb_tables = ddb_items
        inventory = inv

    account_id = get_account_id()
    aliases: Dict[str, Set[str]] = {}

    def register_node(canonical_id: str, alt_ids: List[str], **attrs):
        all_ids = set([canonical_id] + [a for a in alt_ids if a])
        for nid in all_ids:
            G.add_node(nid, **attrs)
            if nid not in aliases:
                aliases[nid] = set()
            aliases[nid].update(all_ids)

    # 1. Add User nodes
    for u in inventory.users:
        u_id = get_node_id("User", u['name'])
        register_node(
            u_id, [u.get('arn')],
            type='User',
            label=u['name'],
            riskScore=u.get('riskScore', 0),
            arn=u['arn'],
            description=f"IAM User: {u['name']}"
        )

    # 2. Add Group nodes
    for g in inventory.groups:
        g_id = get_node_id("Group", g['name'])
        register_node(
            g_id, [g.get('arn')],
            type='Group',
            label=g['name'],
            riskScore=0,
            arn=g['arn'],
            description=f"IAM Group: {g['name']}"
        )

    # 3. Add Role nodes
    for r in inventory.roles:
        r_id = get_node_id("Role", r['name'])
        register_node(
            r_id, [r.get('arn')],
            type='Role',
            label=r['name'],
            riskScore=r.get('riskScore', 0),
            arn=r['arn'],
            description=r.get('description', '')
        )

    # 4. Add Policy nodes
    for p in inventory.policies:
        p_id = get_node_id("Policy", p['name'])
        register_node(
            p_id, [p.get('arn')],
            type='Policy',
            label=p['name'],
            riskScore=p.get('riskScore', 0),
            arn=p.get('arn', ''),
            description=p.get('document', '')
        )

    # 5. Add S3 nodes
    for s in inventory.s3:
        s_id = get_node_id("S3", s['name'])
        register_node(
            s_id, [s.get('arn')],
            type='S3',
            label=s['name'],
            riskScore=s.get('riskScore', 0),
            arn=s['arn'],
            description=f"S3 Bucket: {s['name']}",
            region=s.get('region', 'us-east-1')
        )

    # 6. Add EC2 nodes (RUNNING instances only)
    from app.services.aws.ec2_service import is_running_ec2
    running_ec2 = [e for e in inventory.ec2 if is_running_ec2(e)]
    for e in running_ec2:
        e_id = get_node_id("EC2", e['id'])
        register_node(
            e_id, [e['id'], e.get('arn')],
            type='EC2',
            label=e['name'],
            riskScore=e.get('riskScore', 0),
            arn=e['arn'],
            description=f"EC2 Instance: {e['name']}",
            region=e.get('region', 'unknown'),
            state='running',
            status='active'
        )

    # 7. Add Lambda nodes
    for l in inventory.lambdas:
        l_id = get_node_id("Lambda", l['name'])
        register_node(
            l_id, [l.get('arn')],
            type='Lambda',
            label=l['name'],
            riskScore=l.get('riskScore', 0),
            arn=l['arn'],
            description=f"Lambda Function: {l['name']}"
        )

    # 8. Add Secrets nodes
    for sec in inventory.secrets:
        sec_id = get_node_id("Secrets", sec['name'])
        register_node(
            sec_id, [sec.get('arn')],
            type='Secrets',
            label=sec['name'],
            riskScore=sec.get('riskScore', 0),
            arn=sec['arn'],
            description=f"Secret: {sec['name']}"
        )

    # 9. Add RDS nodes
    for rds in inventory.rds:
        rds_id = get_node_id("RDS", rds['name'])
        register_node(
            rds_id, [rds.get('arn')],
            type='RDS',
            label=rds['name'],
            riskScore=rds.get('riskScore', 0),
            arn=rds['arn'],
            description=f"RDS Instance: {rds['name']}"
        )

    # 10. Add DynamoDB nodes
    for ddb in inventory.dynamodb:
        ddb_id = get_node_id("DynamoDB", ddb['name'])
        register_node(
            ddb_id, [ddb.get('arn')],
            type='DynamoDB',
            label=ddb['name'],
            riskScore=ddb.get('riskScore', 0),
            arn=ddb['arn'],
            description=f"DynamoDB Table: {ddb['name']}"
        )

    # Helper for adding semantically validated edges with provenance and alias propagation
    def safe_add_edge(u: str, v: str, label: str, **attrs) -> bool:
        if not (G.has_node(u) and G.has_node(v)):
            return False
        u_type = G.nodes[u].get('type', 'Resource')
        v_type = G.nodes[v].get('type', 'Resource')
        is_valid, diag = validate_edge(u_type, label, v_type)
        if not is_valid:
            logger.warning(f"Edge rejected by semantic validation: {diag}")
            return False

        prov = dict(attrs)
        if "provenance" in attrs and isinstance(attrs["provenance"], dict):
            prov.update(attrs["provenance"])
        prov.setdefault("relationship", label)
        prov.setdefault("edge_type", label)
        prov.setdefault("decision", attrs.get("decision", "ALLOW"))
        prov.setdefault("why", attrs.get("why", ""))

        edge_kwargs = dict(attrs)
        edge_kwargs.setdefault("label", label)
        edge_kwargs.setdefault("relationship", label)
        edge_kwargs["provenance"] = prov

        u_targets = aliases.get(u, {u})
        v_targets = aliases.get(v, {v})
        for u_n in u_targets:
            for v_n in v_targets:
                if G.has_node(u_n) and G.has_node(v_n):
                    G.add_edge(u_n, v_n, **edge_kwargs)
        return True

    # --- Build Relationships with Provenance ---

    # 1. Users -> Groups
    for u in inventory.users:
        u_id = get_node_id("User", u['name'])
        for g_name in u.get('groups', []):
            g_id = get_node_id("Group", g_name)
            safe_add_edge(
                u_id, g_id, 'MEMBER_OF',
                edge_type='MEMBER_OF',
                source='IAM',
                principal=u['name'],
                principal_type='User',
                decision='ALLOWED',
                why=f"IAM Group Membership: IAM user '{u['name']}' is a member of group '{g_name}'"
            )

    # 2. Users -> Policies
    for u in inventory.users:
        u_id = get_node_id("User", u['name'])
        raw_policies = u.get('policies') or []
        if not raw_policies:
            raw_policies = [p['name'] if isinstance(p, dict) else p for p in (u.get('attached_policies') or u.get('attachedPolicies') or [])]
        for p_name in raw_policies:
            clean_name = p_name.replace('[inline] ', '')
            p_id = get_node_id("Policy", clean_name)
            safe_add_edge(
                u_id, p_id, 'HAS_POLICY',
                edge_type='HAS_POLICY',
                source='IAM',
                principal=u['name'],
                principal_type='User',
                policy_name=clean_name,
                policy_arn=p_id,
                decision='ALLOWED',
                why=f"IAM user '{u['name']}' has policy '{clean_name}' attached"
            )

    # 3. Groups -> Policies
    for g in inventory.groups:
        g_id = get_node_id("Group", g['name'])
        raw_policies = g.get('attachedPolicies') or g.get('attached_policies') or g.get('policies') or []
        clean_policies = [p['name'] if isinstance(p, dict) else p for p in raw_policies]
        for p_name in clean_policies:
            clean_name = p_name.replace('[inline] ', '')
            p_id = get_node_id("Policy", clean_name)
            safe_add_edge(
                g_id, p_id, 'HAS_POLICY',
                edge_type='HAS_POLICY',
                source='IAM',
                principal=g['name'],
                principal_type='Group',
                policy_name=clean_name,
                policy_arn=p_id,
                decision='ALLOWED',
                why=f"IAM group '{g['name']}' has policy '{clean_name}' attached"
            )

    # 4. Roles -> Policies
    for r in inventory.roles:
        r_id = get_node_id("Role", r['name'])
        raw_policies = r.get('attachedPolicies') or r.get('attached_policies') or r.get('policies') or []
        clean_policies = [p['name'] if isinstance(p, dict) else p for p in raw_policies]
        for p_name in clean_policies:
            clean_name = p_name.replace('[inline] ', '')
            p_id = get_node_id("Policy", clean_name)
            safe_add_edge(
                r_id, p_id, 'HAS_POLICY',
                edge_type='HAS_POLICY',
                source='IAM',
                principal=r['name'],
                principal_type='Role',
                policy_name=clean_name,
                policy_arn=p_id,
                decision='ALLOWED',
                why=f"IAM role '{r['name']}' has policy '{clean_name}' attached"
            )

    # 5. EC2 -> Roles (instance profile for running instances)
    for e in running_ec2:
        role_name = e.get('details', {}).get('iam_role_name') or e.get('role')
        if role_name and role_name != 'None':
            e_id = get_node_id("EC2", e['id'])
            r_id = get_node_id("Role", role_name)
            safe_add_edge(
                e_id, r_id, 'ATTACHED_TO',
                relationship='EXECUTES_WITH',
                edge_type='EXECUTES_WITH',
                source='ROLE_ATTACHMENT',
                principal=e['id'],
                principal_type='EC2',
                resource=e['id'],
                region=e.get('region', 'unknown'),
                decision='ALLOWED',
                why=f"Running EC2 instance '{e['id']}' operates under IAM instance profile role '{role_name}' with ec2.amazonaws.com"
            )

    # 6. Lambda -> Roles (execution role)
    for l in inventory.lambdas:
        role_name = l.get('details', {}).get('execution_role') or l.get('role')
        if role_name and role_name != 'None':
            l_id = get_node_id("Lambda", l['name'])
            r_id = get_node_id("Role", role_name)
            safe_add_edge(
                l_id, r_id, 'EXECUTES_WITH',
                edge_type='EXECUTES_WITH',
                source='LAMBDA_CONFIGURATION',
                principal=l['name'],
                principal_type='Lambda',
                resource=l.get('arn', ''),
                region=l.get('region', 'unknown'),
                decision='ALLOWED',
                why=f"Lambda function '{l['name']}' executes with configured IAM role '{role_name}'"
            )

    # 7. AssumeRole Trust: Users/Roles -> CAN_ASSUME -> Role
    _policy_doc_map = {}
    for _p in inventory.policies:
        if _p.get('name') and _p.get('document'):
            _policy_doc_map[_p['name']] = _p['document']

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

        if G.has_node(r_id):
            if trust_ev.get('trust_is_broad'):
                G.nodes[r_id]['trust_is_broad'] = True
                G.nodes[r_id]['trust_principal_types'] = ','.join(
                    sorted(trust_ev.get('trust_principal_types', set()))
                )
            if trust_ev.get('conditional_trusts'):
                G.nodes[r_id]['has_conditional_trust'] = True
                G.nodes[r_id]['conditional_trust_count'] = len(trust_ev['conditional_trusts'])

        for entry in trust_ev.get('users', []):
            if entry['evidence'].get('trust_status') != 'definitive':
                continue
            if not entry['evidence'].get('call_permission_verified'):
                continue
            u = entry['principal']
            u_id = get_node_id("User", u['name'])
            safe_add_edge(
                u_id, r_id, 'CAN_ASSUME',
                edge_type='CAN_ASSUME',
                source='TRUST_POLICY',
                principal=u['name'],
                principal_type='User',
                target_role=r['name'],
                trust_type=entry['evidence']['trust_principal_type'],
                statement_sid=entry['evidence'].get('statement_sid', 'TrustStatement'),
                action=entry['evidence'].get('action', 'sts:AssumeRole'),
                condition_status='SATISFIED',
                decision='ALLOWED',
                why=f"Role '{r['name']}' trust policy grants sts:AssumeRole to user '{u['name']}' with verified call permission"
            )

        for entry in trust_ev.get('roles', []):
            if entry['evidence'].get('trust_status') != 'definitive':
                continue
            if not entry['evidence'].get('call_permission_verified'):
                continue
            src_r = entry['principal']
            src_r_id = get_node_id("Role", src_r['name'])
            if src_r_id != r_id:
                safe_add_edge(
                    src_r_id, r_id, 'CAN_ASSUME',
                    edge_type='CAN_ASSUME',
                    source='TRUST_POLICY',
                    principal=src_r['name'],
                    principal_type='Role',
                    target_role=r['name'],
                    trust_type=entry['evidence']['trust_principal_type'],
                    statement_sid=entry['evidence'].get('statement_sid', 'TrustStatement'),
                    action=entry['evidence'].get('action', 'sts:AssumeRole'),
                    condition_status='SATISFIED',
                    decision='ALLOWED',
                    why=f"Role '{r['name']}' trust policy grants sts:AssumeRole to role '{src_r['name']}' with verified call permission"
                )

    # 8. Policy -> ALLOWS -> Resource via evaluate_policy_allows_resources_with_provenance
    all_resources = (
        inventory.s3 + inventory.secrets + inventory.rds +
        inventory.dynamodb + running_ec2 + inventory.lambdas
    )

    from app.services.attack.policy_evaluator import parse_policy_document, match_action

    for p in inventory.policies:
        p_id = get_node_id("Policy", p['name'])
        doc = p.get('document', '{}')
        p_arn = p.get('arn', '')
        allowed_res, prov_map, _ = evaluate_policy_allows_resources_with_provenance(
            p['name'], p_arn, doc, all_resources, account_id=account_id
        )
        for res in allowed_res:
            res_type = res.get('type')
            item_ident = res.get('id') if res_type == 'EC2' else (res.get('name') or res.get('id'))
            res_id = get_node_id(res_type, item_ident)
            res_key = str(item_ident)
            edge_prov = prov_map.get(res_key, {})
            safe_add_edge(
                p_id, res_id, 'ALLOWS',
                edge_type='ALLOWS',
                source='IAM',
                policy_name=p['name'],
                policy_arn=p_arn,
                statement_sid=edge_prov.get('statement_sid', 'Statement-1'),
                effect=edge_prov.get('effect', 'Allow'),
                action=edge_prov.get('action', '*'),
                resource=str(item_ident),
                resource_arn=edge_prov.get('resource_arn', ''),
                condition_status=edge_prov.get('condition_status', 'NONE'),
                decision=edge_prov.get('decision', 'ALLOWED'),
                region=edge_prov.get('region', 'global'),
                why=edge_prov.get('why', f"Policy '{p['name']}' allows access to {res_type} '{item_ident}'"),
                evidence=edge_prov.get('evidence', {})
            )

        # 9. IAM Database Authentication: Policy -> DB_CONNECT -> AuroraDBUser -> BELONGS_TO -> RDS
        stmts = parse_policy_document(doc)
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            act_list = stmt.get("Action", [])
            if not any(match_action(a, "rds-db:connect") for a in act_list):
                continue
            sid = stmt.get("Sid") or "Statement-DBConnect"
            for r_pattern in stmt.get("Resource", []):
                if "arn:aws:rds-db:" in r_pattern:
                    try:
                        parts = r_pattern.split(":dbuser:")
                        if len(parts) == 2:
                            db_user_part = parts[1]
                            cluster_id, db_user = db_user_part.split("/", 1)
                            db_user_clean = db_user.replace("*", "").strip() or "db_user"
                            db_node_id = f"aws:dbuser:{cluster_id}:{db_user_clean}"
                            if not G.has_node(db_node_id):
                                G.add_node(
                                    db_node_id,
                                    type="AuroraDBUser",
                                    label=f"{db_user_clean} ({cluster_id})",
                                    riskScore=25,
                                    arn=r_pattern,
                                    description=f"IAM Authenticated Database User: {db_user_clean} on {cluster_id}"
                                )
                            safe_add_edge(
                                p_id, db_node_id, 'DB_CONNECT',
                                edge_type='DB_CONNECT',
                                source='IAM',
                                policy_name=p['name'],
                                policy_arn=p_arn,
                                statement_sid=sid,
                                effect='Allow',
                                action='rds-db:connect',
                                resource=db_user_clean,
                                resource_arn=r_pattern,
                                decision='ALLOWED',
                                why=f"Policy '{p['name']}' grants rds-db:connect permission to DB user '{db_user_clean}'"
                            )

                            # Link to matching RDS cluster or instance if present
                            for rds_res in inventory.rds:
                                r_ident = rds_res.get("name") or rds_res.get("id")
                                if cluster_id.lower() in str(r_ident).lower() or cluster_id.lower() in str(rds_res.get("arn", "")).lower():
                                    rds_node_id = get_node_id("RDS", r_ident)
                                    safe_add_edge(
                                        db_node_id, rds_node_id, 'BELONGS_TO',
                                        edge_type='BELONGS_TO',
                                        source='AWS_RESOURCE',
                                        decision='ALLOWED',
                                        why=f"Database user '{db_user_clean}' belongs to RDS database '{r_ident}'"
                                    )
                                    # Also link identities holding this policy directly to the RDS instance
                                    for u in inventory.users:
                                        if p['name'] in u.get('policies', []):
                                            u_id = get_node_id("User", u['name'])
                                            safe_add_edge(
                                                u_id, rds_node_id, 'DB_CONNECT',
                                                edge_type='DB_CONNECT',
                                                source='IAM',
                                                policy_name=p['name'],
                                                policy_arn=p_arn,
                                                statement_sid=sid,
                                                effect='Allow',
                                                action='rds-db:connect',
                                                resource=r_ident,
                                                decision='ALLOWED',
                                                why=f"IAM user '{u['name']}' has policy '{p['name']}' granting rds-db:connect to RDS database '{r_ident}'"
                                            )
                    except Exception as e:
                        logger.debug(f"Failed parsing rds-db ARN {r_pattern}: {e}")

    logger.info(f"Built local NetworkX Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G
