import logging
from datetime import datetime
from app.services.aws.session import get_aws_session

logger = logging.getLogger("scanner")


def collect_recent_alerts() -> list:
    alerts = []
    try:
        session = get_aws_session()
        client = session.client('cloudtrail')

        # Lookup recent events - AWS only allows one LookupAttribute per call
        all_events = []
        for event_name in ['AssumeRole', 'PutBucketPolicy', 'CreateUser', 'AttachUserPolicy',
                           'CreateAccessKey', 'PutRolePolicy', 'DeleteBucketPolicy']:
            try:
                response = client.lookup_events(
                    LookupAttributes=[
                        {'AttributeKey': 'EventName', 'AttributeValue': event_name}
                    ],
                    MaxResults=5
                )
                all_events.extend(response.get('Events', []))
            except Exception:
                pass

        for event in all_events:
            event_id = event['EventId']
            time = event.get('EventTime', datetime.utcnow())
            username = event.get('Username', 'Unknown')
            name = event.get('EventName', 'ConfigDrift')

            # Map severity based on event type
            severity = 'medium'
            if name in ['PutBucketPolicy', 'DeleteBucketPolicy']:
                severity = 'high'
            elif name in ['AttachUserPolicy', 'PutRolePolicy', 'CreateAccessKey']:
                severity = 'high'
            elif name == 'AssumeRole' and 'Admin' in event.get('CloudTrailEvent', ''):
                severity = 'critical'
            elif name == 'CreateUser':
                severity = 'medium'

            res_list = event.get('Resources', [])
            resource_name = res_list[0]['ResourceName'] if res_list else 'AWSResource'

            alerts.append({
                "id": event_id,
                "timestamp": time.isoformat() + "Z" if hasattr(time, 'isoformat') else str(time),
                "severity": severity,
                "resource": resource_name,
                "description": f"CloudTrail Audit Alert: {name} action executed by {username}.",
                "status": "open",
                "details": event.get('CloudTrailEvent', '{}')
            })
        logger.info(f"CloudTrail Collector: Discovered {len(alerts)} alerts")
    except Exception as e:
        logger.error(f"CloudTrail Collector failed to list events: {str(e)}")
    return alerts
