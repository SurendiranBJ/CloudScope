import logging
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
            
        # 10. Write Relationships
        # Connect Users to Groups
        for u in inventory.users:
            for g_name in u['groups']:
                execute_write(
                    "MATCH (u:User {label: $username}), (g:Group {label: $gname}) "
                    "CREATE (u)-[:MEMBER_OF]->(g)",
                    {"username": u['name'], "gname": g_name}
                )
                
        # Connect Users to Policies
        for u in inventory.users:
            for p_name in u['policies']:
                execute_write(
                    "MATCH (u:User {label: $username}), (p:Policy {label: $pname}) "
                    "CREATE (u)-[:HAS_POLICY]->(p)",
                    {"username": u['name'], "pname": p_name}
                )
                
        # Connect Group to Policy (Simulate default rules)
        execute_write(
            "MATCH (g:Group {label: 'Admins'}), (p:Policy {label: 'AdministratorAccess'}) "
            "CREATE (g)-[:HAS_POLICY]->(p)"
        )
        
        # Connect EC2 profile roles
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
                
        # Connect policies to roles targets allowing access (Assume Role trust policies / allow access)
        # Custom logic representing our primary lateral paths:
        execute_write(
            "MATCH (p:Policy {label: 'AdminAssumeRolePolicy'}), (r:Role {label: 'AWSAdminRole'}) "
            "CREATE (p)-[:CAN_ASSUME]->(r)"
        )
        execute_write(
            "MATCH (r:Role {label: 'AWSAdminRole'}), (s:S3 {label: 'S3-Customer-PII-DB'}) "
            "CREATE (r)-[:ALLOWS]->(s)"
        )
        execute_write(
            "MATCH (r:Role {label: 'EC2InstanceProfileRole'}), (sec:Role {label: 'SecretsReaderRole'}) "
            "CREATE (r)-[:CAN_ASSUME]->(sec)"
        )
        execute_write(
            "MATCH (r:Role {label: 'SecretsReaderRole'}), (s:Secrets {label: 'Secrets-RDS-Master'}) "
            "CREATE (r)-[:ALLOWS]->(s)"
        )
        
        logger.info("Successfully populated all nodes and relationships inside Neo4j database")
    except Exception as e:
        logger.error(f"Failed to build graph in Neo4j: {str(e)}")
        raise e
