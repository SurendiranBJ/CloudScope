import logging
import json
from app.database import execute_write
from app.services.scanner.inventory import AWSInventory

logger = logging.getLogger("scanner")


def build_graph_in_neo4j(inventory: AWSInventory):
    logger.info("Initializing Neo4j Graph DB update rebuild")
    try:
        # 1. Clear database elements
        execute_write("MATCH (n) DETACH DELETE n")

        # 2. Write Users
        for u in inventory.users:
            execute_write(
                "CREATE (n:User {id: $id, label: $username, arn: $arn, mfaEnabled: $mfa, riskScore: $riskScore, type: 'User'})",
                {"id": u['id'], "username": u['name'], "arn": u['arn'], "mfa": u['mfaEnabled'], "riskScore": u.get('riskScore', 0)}
            )

        # 3. Write Groups
        for g in inventory.groups:
            execute_write(
                "CREATE (n:Group {id: $id, label: $name, arn: $arn, type: 'Group'})",
                {"id": g['id'], "name": g['name'], "arn": g['arn']}
            )

        # 4. Write Roles
        for r in inventory.roles:
            execute_write(
                "CREATE (n:Role {id: $id, label: $name, arn: $arn, trustPolicy: $trust, riskScore: $riskScore, description: $desc, type: 'Role'})",
                {"id": r['name'], "name": r['name'], "arn": r['arn'], "trust": r['trustPolicy'], "riskScore": r.get('riskScore', 0), "desc": r['description']}
            )

        # 5. Write Policies
        for p in inventory.policies:
            execute_write(
                "CREATE (n:Policy {id: $id, label: $name, arn: $arn, document: $doc, isManaged: $managed, riskScore: $riskScore, type: 'Policy'})",
                {"id": p['name'], "name": p['name'], "arn": p['arn'], "doc": p['document'], "managed": p['type'] == "aws-managed", "riskScore": p.get('riskScore', 0)}
            )

        # 6. Write S3
        for s in inventory.s3:
            execute_write(
                "CREATE (n:S3 {id: $id, label: $name, arn: $arn, region: $reg, riskScore: $riskScore, status: $status, owner: $owner, type: 'S3'})",
                {"id": s['id'], "name": s['name'], "arn": s['arn'], "reg": s['region'], "riskScore": s.get('riskScore', 0), "status": s['status'], "owner": s['owner']}
            )

        # 7. Write EC2
        for e in inventory.ec2:
            execute_write(
                "CREATE (n:EC2 {id: $id, label: $name, arn: $arn, region: $reg, riskScore: $riskScore, status: $status, owner: $owner, type: 'EC2'})",
                {"id": e['id'], "name": e['name'], "arn": e['arn'], "reg": e['region'], "riskScore": e.get('riskScore', 0), "status": e['status'], "owner": e['owner']}
            )

        # 8. Write Lambda
        for l in inventory.lambdas:
            execute_write(
                "CREATE (n:Lambda {id: $id, label: $name, arn: $arn, region: $reg, riskScore: $riskScore, status: $status, owner: $owner, type: 'Lambda'})",
                {"id": l['id'], "name": l['name'], "arn": l['arn'], "reg": l['region'], "riskScore": l.get('riskScore', 0), "status": l['status'], "owner": l['owner']}
            )

        # 9. Write Secrets
        for sec in inventory.secrets:
            execute_write(
                "CREATE (n:Secrets {id: $id, label: $name, arn: $arn, region: $reg, riskScore: $riskScore, status: $status, owner: $owner, type: 'Secrets'})",
                {"id": sec['id'], "name": sec['name'], "arn": sec['arn'], "reg": sec['region'], "riskScore": sec.get('riskScore', 0), "status": sec['status'], "owner": sec['owner']}
            )

        # 9.5 Write RDS & DynamoDB
        for rds in inventory.rds:
            execute_write(
                "CREATE (n:RDS {id: $id, label: $name, arn: $arn, region: $reg, riskScore: $riskScore, status: $status, owner: $owner, type: 'RDS'})",
                {"id": rds['id'], "name": rds['name'], "arn": rds['arn'], "reg": rds['region'], "riskScore": rds.get('riskScore', 0), "status": rds['status'], "owner": rds['owner']}
            )
            
        for ddb in inventory.dynamodb:
            execute_write(
                "CREATE (n:DynamoDB {id: $id, label: $name, arn: $arn, region: $reg, riskScore: $riskScore, status: $status, owner: $owner, type: 'DynamoDB'})",
                {"id": ddb['id'], "name": ddb['name'], "arn": ddb['arn'], "reg": ddb['region'], "riskScore": ddb.get('riskScore', 0), "status": ddb['status'], "owner": ddb['owner']}
            )

        # 10. Write Relationships — all dynamically computed

        # Connect Users to Groups
        for u in inventory.users:
            for g_name in u.get('groups', []):
                execute_write(
                    "MATCH (u:User {label: $username}), (g:Group {label: $gname}) "
                    "CREATE (u)-[:MEMBER_OF]->(g)",
                    {"username": u['name'], "gname": g_name}
                )

        # Connect Users to Policies
        for u in inventory.users:
            for p_name in u.get('policies', []):
                clean_name = p_name.replace('[inline] ', '')
                execute_write(
                    "MATCH (u:User {label: $username}), (p:Policy {label: $pname}) "
                    "CREATE (u)-[:HAS_POLICY]->(p)",
                    {"username": u['name'], "pname": clean_name}
                )

        # Connect Roles to their attached policies
        for r in inventory.roles:
            for p_name in r.get('attachedPolicies', []):
                execute_write(
                    "MATCH (r:Role {label: $rolename}), (p:Policy {label: $pname}) "
                    "CREATE (r)-[:HAS_POLICY]->(p)",
                    {"rolename": r['name'], "pname": p_name}
                )

        # Connect EC2 instance profile roles
        for e in inventory.ec2:
            role_name = e['details'].get('iam_role_name', 'None')
            if role_name != 'None':
                execute_write(
                    "MATCH (e:EC2 {label: $ec2name}), (r:Role {label: $rolename}) "
                    "CREATE (e)-[:ATTACHED_TO]->(r)",
                    {"ec2name": e['name'], "rolename": role_name}
                )

        # Connect Lambda execution roles
        for l in inventory.lambdas:
            role_name = l['details'].get('execution_role', 'None')
            if role_name != 'None':
                execute_write(
                    "MATCH (l:Lambda {label: $lambdaname}), (r:Role {label: $rolename}) "
                    "CREATE (l)-[:EXECUTES_WITH]->(r)",
                    {"lambdaname": l['name'], "rolename": role_name}
                )

        # Connect Roles via trust policies (dynamic AssumeRole relationships)
        role_names = {r['name'] for r in inventory.roles}
        user_names = {u['name'] for u in inventory.users}
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
                            if ':role/' in p_arn:
                                source_name = p_arn.split('/')[-1]
                                if source_name in role_names and source_name != r['name']:
                                    execute_write(
                                        "MATCH (s:Role {label: $source}), (t:Role {label: $target}) "
                                        "CREATE (s)-[:CAN_ASSUME]->(t)",
                                        {"source": source_name, "target": r['name']}
                                    )
                            elif ':user/' in p_arn:
                                source_name = p_arn.split('/')[-1]
                                if source_name in user_names:
                                    execute_write(
                                        "MATCH (u:User {label: $username}), (r:Role {label: $rolename}) "
                                        "CREATE (u)-[:CAN_ASSUME]->(r)",
                                        {"username": source_name, "rolename": r['name']}
                                    )
            except (json.JSONDecodeError, Exception):
                pass

        # Connect Roles to Resources via policy name heuristics
        for r in inventory.roles:
            for p_name in r.get('attachedPolicies', []):
                p_lower = p_name.lower()
                if 's3' in p_lower or 'storage' in p_lower or 'admin' in p_lower:
                    for s in inventory.s3:
                        execute_write(
                            "MATCH (r:Role {label: $rolename}), (s:S3 {label: $sname}) "
                            "CREATE (r)-[:ALLOWS]->(s)",
                            {"rolename": r['name'], "sname": s['name']}
                        )
                if 'secret' in p_lower or 'admin' in p_lower:
                    for sec in inventory.secrets:
                        execute_write(
                            "MATCH (r:Role {label: $rolename}), (s:Secrets {label: $sname}) "
                            "CREATE (r)-[:ALLOWS]->(s)",
                            {"rolename": r['name'], "sname": sec['name']}
                        )

        logger.info("Successfully populated all nodes and relationships inside Neo4j database")
    except Exception as e:
        logger.error(f"Failed to build graph in Neo4j: {str(e)}")
        raise e
