import logging
import concurrent.futures
import time
from datetime import datetime
from app.services.aws.session import get_aws_session

logger = logging.getLogger("scanner")


def collect_recent_alerts() -> list:
    alerts = []
    try:
        session = get_aws_session()
        client = session.client('cloudtrail')

        event_names = ['AssumeRole', 'PutBucketPolicy', 'CreateUser', 'AttachUserPolicy',
                       'CreateAccessKey', 'PutRolePolicy', 'DeleteBucketPolicy']

        all_events = []
        start_time = time.time()

        def fetch_events_for_name(event_name):
            try:
                response = client.lookup_events(
                    LookupAttributes=[
                        {'AttributeKey': 'EventName', 'AttributeValue': event_name}
                    ],
                    MaxResults=5
                )
                return response.get('Events', [])
            except Exception as e:
                logger.debug(f"Failed to lookup CloudTrail events for {event_name}: {e}")
                return []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(fetch_events_for_name, event_names)
            for events in results:
                all_events.extend(events)

        elapsed = time.time() - start_time
        logger.info(f"CloudTrail collection step completed in {elapsed:.2f}s")

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
