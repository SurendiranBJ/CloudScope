import logging
from datetime import datetime
from app.services.aws.session import get_aws_session, get_account_id

logger = logging.getLogger("scanner")


def collect_secrets() -> list:
    secrets = []
    try:
        session = get_aws_session()
        client = session.client('secretsmanager')
        account_id = get_account_id()
        paginator = client.get_paginator('list_secrets')

        for page in paginator.paginate():
            for sec in page.get('SecretList', []):
                name = sec['Name']
                arn = sec['ARN']
                rotation = sec.get('RotationEnabled', False)
                last_changed = sec.get('LastChangedDate', datetime.utcnow())
                last_accessed = sec.get('LastAccessedDate')
                created = sec.get('CreatedDate')
                description = sec.get('Description', '')

                # Get owner from tags
                owner = account_id
                tags = sec.get('Tags', [])
                for tag in tags:
                    if tag['Key'] == 'Owner':
                        owner = tag['Value']
                        break

                secrets.append({
                    "id": name,
                    "name": name,
                    "type": "Secrets",
                    "region": session.region_name or "ap-south-1",
                    "riskScore": 0,  # Calculated downstream
                    "status": "configured" if rotation else "warning",
                    "owner": owner,
                    "arn": arn,
                    "details": {
                        "rotation_enabled": rotation,
                        "last_changed": last_changed.isoformat() if hasattr(last_changed, 'isoformat') else str(last_changed),
                        "last_accessed": last_accessed.isoformat() if last_accessed and hasattr(last_accessed, 'isoformat') else "Never",
                        "description": description
                    }
                })
        logger.info(f"Secrets Collector: Discovered {len(secrets)} secrets")
    except Exception as e:
        logger.error(f"Secrets Collector failed to list secrets: {str(e)}")
    return secrets
